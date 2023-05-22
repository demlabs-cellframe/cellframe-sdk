/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2019
 * All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

 DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
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
#include "dap_chain_global_db.h"
#include "dap_enc.h"
#include <dap_enc_http.h>
#include <dap_enc_key.h>
#include <dap_enc_ks.h>
#include "dap_chain_mempool.h"
#include "dap_chain_mempool_rpc.h"

#include "dap_common.h"
#include "dap_list.h"
#include "dap_chain.h"
#include "dap_chain_net.h"
#include "dap_chain_net_tx.h"
#include "dap_sign.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_net_srv.h"

#define LOG_TAG "dap_chain_mempool"

int dap_datum_mempool_init(void)
{
    dap_chain_mempool_rpc_init();
    return 0;
}

/**
 * @brief dap_chain_mempool_datum_add
 * @param a_datum
 * @return
 */
char *dap_chain_mempool_datum_add(const dap_chain_datum_t *a_datum, dap_chain_t *a_chain)
{
    if( a_datum == NULL){
        log_it(L_ERROR, "NULL datum trying to add in mempool");
        return NULL;
    }

    dap_chain_hash_fast_t l_key_hash;

    dap_hash_fast(a_datum->data, a_datum->header.data_size, &l_key_hash);
    char * l_key_str = dap_chain_hash_fast_to_str_new(&l_key_hash);
    char * l_gdb_group = dap_chain_net_get_gdb_group_mempool(a_chain);

    if (dap_chain_global_db_gr_set(l_key_str, a_datum, dap_chain_datum_size(a_datum), l_gdb_group)) {
        log_it(L_NOTICE, "Datum with hash %s was placed in mempool", l_key_str);
    } else {
        log_it(L_WARNING, "Can't place datum with hash %s in mempool", l_key_str);
        DAP_DEL_Z(l_key_str);
    }
    DAP_DELETE(l_gdb_group);
    return l_key_str;
}

/**
 * Make transfer transaction & insert to cache
 *
 * return 0 Ok, -2 not enough funds to transfer, -1 other Error
 */
dap_hash_fast_t* dap_chain_mempool_tx_create(dap_chain_t * a_chain, dap_enc_key_t *a_key_from,
        const dap_chain_addr_t* a_addr_from, const dap_chain_addr_t* a_addr_to,
        const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
        uint256_t a_value, uint256_t a_value_fee)
{
    // check valid param
    if(!a_chain | !a_key_from || ! a_addr_from || !a_key_from->priv_key_data || !a_key_from->priv_key_data_size ||
            !dap_chain_addr_check_sum(a_addr_from) || (a_addr_to && !dap_chain_addr_check_sum(a_addr_to)) || IS_ZERO_256(a_value))
        return NULL;

    const char *l_native_ticker = dap_chain_net_by_id(a_chain->net_id)->pub.native_ticker;
    bool l_single_channel = !dap_strcmp(a_token_ticker, l_native_ticker);
    // find the transactions from which to take away coins
    uint256_t l_value_transfer = {}; // how many coins to transfer
    uint256_t l_value_need = a_value, l_net_fee = {}, l_total_fee = {}, l_fee_transfer = {};
    dap_chain_addr_t l_addr_fee = {};
    dap_list_t *l_list_fee_out = NULL;
    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_chain->net_id, &l_net_fee, &l_addr_fee);
    SUM_256_256(l_net_fee, a_value_fee, &l_total_fee);
    if (l_single_channel)
        SUM_256_256(l_value_need, l_total_fee, &l_value_need);
    else {
        l_list_fee_out = dap_chain_ledger_get_list_tx_outs_with_val(a_chain->ledger, l_native_ticker,
                                                                    a_addr_from, l_total_fee, &l_fee_transfer);
        if (!l_list_fee_out) {
            log_it(L_WARNING, "Not enough funds to pay fee");
            return NULL;
        }
    }
    dap_list_t *l_list_used_out = dap_chain_ledger_get_list_tx_outs_with_val(a_chain->ledger, a_token_ticker,
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

    if (l_single_channel) { // add 'out' items
        uint256_t l_value_pack = {}; // how much datoshi add to 'out' items
        if (dap_chain_datum_tx_add_out_item(&l_tx, a_addr_to, a_value) == 1) {
            SUM_256_256(l_value_pack, a_value, &l_value_pack);
        } else {
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
        // Network fee
        if (l_net_fee_used) {
            if (dap_chain_datum_tx_add_out_item(&l_tx, &l_addr_fee, l_net_fee) == 1)
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
        uint256_t l_value_back;
        SUBTRACT_256_256(l_value_transfer, l_value_pack, &l_value_back);
        if(!IS_ZERO_256(l_value_back)) {
            if(dap_chain_datum_tx_add_out_item(&l_tx, a_addr_from, l_value_back) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
            }
        }
    } else { // add 'out_ext' items
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_addr_to, a_value, a_token_ticker) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
        // coin back
        uint256_t l_value_back;
        SUBTRACT_256_256(l_value_transfer, a_value, &l_value_back);
        if(!IS_ZERO_256(l_value_back)) {
            if(dap_chain_datum_tx_add_out_ext_item(&l_tx, a_addr_from, l_value_back, a_token_ticker) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
            }
        }
        // Network fee
        if (l_net_fee_used) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr_fee, l_net_fee, l_native_ticker) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
            }
        }
        // Validator's fee
        if (!IS_ZERO_256(a_value_fee)) {
            if (dap_chain_datum_tx_add_fee_item(&l_tx, a_value_fee) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
            }
        }
        // fee coin back
        SUBTRACT_256_256(l_fee_transfer, l_total_fee, &l_value_back);
        if(!IS_ZERO_256(l_value_back)) {
            if(dap_chain_datum_tx_add_out_ext_item(&l_tx, a_addr_from, l_value_back, l_native_ticker) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
            }
        }
    }

    // add 'sign' items
    if(dap_chain_datum_tx_add_sign_item(&l_tx, a_key_from) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }

    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, l_tx_size);
    dap_hash_fast_t * l_ret = DAP_NEW_Z(dap_hash_fast_t);
    dap_hash_fast(l_tx, l_tx_size, l_ret);
    DAP_DELETE(l_tx);
    char *l_hash_str = dap_chain_mempool_datum_add(l_datum, a_chain);

    DAP_DELETE( l_datum );

    if (l_hash_str) {
        DAP_DELETE(l_hash_str);
        return l_ret;
    }else{
        DAP_DELETE(l_ret);
        return NULL;
    }
}

/**
 * Make transfer transaction & insert to cache
 *
 * return 0 Ok, -2 not enough funds to transfer, -1 other Error
 */
int dap_chain_mempool_tx_create_massive( dap_chain_t * a_chain, dap_enc_key_t *a_key_from,
        const dap_chain_addr_t* a_addr_from, const dap_chain_addr_t* a_addr_to,
        const char a_token_ticker[10],
        uint256_t a_value, uint256_t a_value_fee,size_t a_tx_num)
{
    // check valid param
    if(!a_chain | !a_key_from || !a_addr_from || !a_key_from->priv_key_data || !a_key_from->priv_key_data_size ||
            !dap_chain_addr_check_sum(a_addr_from) || !dap_chain_addr_check_sum(a_addr_to) ||
            IS_ZERO_256(a_value) || !a_tx_num){
        log_it(L_ERROR, "Wrong parameters in dap_chain_mempool_tx_create_massive() call");
        return -1;

    }
    const char *l_native_ticker = dap_chain_net_by_id(a_chain->net_id)->pub.native_ticker;
    if (dap_strcmp(a_token_ticker, l_native_ticker)) {
        log_it(L_WARNING, "dap_chain_mempool_tx_create_massive() should only be used with native token");
        return -2;
    }

    dap_global_db_obj_t * l_objs = DAP_NEW_Z_SIZE(dap_global_db_obj_t, (a_tx_num + 1) * sizeof (dap_global_db_obj_t));
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
    char *l_balance = dap_chain_balance_to_coins(l_value_need);
    log_it(L_DEBUG, "Create %"DAP_UINT64_FORMAT_U" transactions, summary %s", a_tx_num, l_balance);
    DAP_DELETE(l_balance);
    dap_list_t *l_list_used_out = dap_chain_ledger_get_list_tx_outs_with_val(a_chain->ledger, a_token_ticker,
                                                                             a_addr_from, l_value_need, &l_value_transfer);
    if (!l_list_used_out) {
        log_it(L_WARNING,"Not enough funds to transfer");
        DAP_DELETE(l_objs);
        return -2;
    }

    dap_chain_hash_fast_t l_tx_new_hash = {0};
    for (size_t i=0; i< a_tx_num ; i++){
        log_it(L_DEBUG, "Prepare tx %zu",i);
        // find the transactions from which to take away coins

        // create empty transaction
        dap_chain_datum_tx_t *l_tx_new = dap_chain_datum_tx_create();
        uint256_t l_value_back = {};
        // add 'in' items
        dap_list_t *l_list_tmp = l_list_used_out;
        uint256_t l_value_to_items = {}; // how many coins to transfer

        // Add in and remove out used items
        while(l_list_tmp) {
            list_used_item_t *l_item = l_list_tmp->data;
            char l_in_hash_str[70];

            dap_chain_hash_fast_to_str(&l_item->tx_hash_fast,l_in_hash_str,sizeof (l_in_hash_str) );

            char *l_balance = dap_chain_balance_print(l_item->value);
            if (dap_chain_datum_tx_add_in_item(&l_tx_new, &l_item->tx_hash_fast, l_item->num_idx_out)) {
                SUM_256_256(l_value_to_items, l_item->value, &l_value_to_items);
                log_it(L_DEBUG, "Added input %s with %s datoshi", l_in_hash_str, l_balance);
            }else{
                log_it(L_WARNING, "Can't add input from %s with %s datoshi", l_in_hash_str, l_balance);
            }
            DAP_DELETE(l_balance);
            l_list_used_out = l_list_tmp->next;
            DAP_DELETE(l_list_tmp->data);
            dap_list_free1(l_list_tmp);
            l_list_tmp = l_list_used_out;
            if (compare256(l_value_to_items, l_value_transfer) != -1)
                break;
        }
        if (compare256(l_value_to_items, l_single_val) == -1) {
            char *l_balance = dap_chain_balance_print(l_value_to_items);
            char *l_balance_need = dap_chain_balance_print(l_single_val);
            log_it(L_ERROR, "Not enough values on output to produce enough inputs: %s when need %s", l_balance, l_balance_need);
            DAP_DELETE(l_balance);
            DAP_DELETE(l_balance_need);
            DAP_DELETE(l_objs);
            return -5;
        }

        // add 'out' items
        uint256_t l_value_pack = {}; // how much coin add to 'out' items
        if (dap_chain_datum_tx_add_out_item(&l_tx_new, a_addr_to, a_value) == 1)
            SUM_256_256(l_value_pack, a_value, &l_value_pack);
        else {
            dap_chain_datum_tx_delete(l_tx_new);
            DAP_DELETE(l_objs);
            return -3;
        }
        // Network fee
        if (l_net_fee_used) {
            if (dap_chain_datum_tx_add_out_item(&l_tx_new, &l_addr_fee, l_net_fee) == 1)
                SUM_256_256(l_value_pack, l_net_fee, &l_value_pack);
            else {
                dap_chain_datum_tx_delete(l_tx_new);
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
                DAP_DELETE(l_objs);
                return -3;
            }
        }
        // coin back
        SUBTRACT_256_256(l_value_transfer, l_value_pack, &l_value_back);
        if (!IS_ZERO_256(l_value_back)) {
            if(dap_chain_datum_tx_add_out_item(&l_tx_new, a_addr_from, l_value_back) != 1) {
                dap_chain_datum_tx_delete(l_tx_new);
                DAP_DELETE(l_objs);
                return -3;
            }
        }

        // add 'sign' items
        if(dap_chain_datum_tx_add_sign_item(&l_tx_new, a_key_from) != 1) {
            dap_chain_datum_tx_delete(l_tx_new);
            DAP_DELETE(l_objs);
            return -4;
        }
        // now tx is formed - calc size and hash
        size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx_new);

        dap_hash_fast(l_tx_new, l_tx_size, &l_tx_new_hash);
        // If we have value back - update balance cache
        if (!IS_ZERO_256(l_value_back)) {
            //log_it(L_DEBUG,"We have value back %"DAP_UINT64_FORMAT_U" now lets see how many outputs we have", l_value_back);
            int l_item_count = 0;
            dap_list_t *l_list_out_items = dap_chain_datum_tx_items_get( l_tx_new, TX_ITEM_TYPE_OUT_ALL,
                    &l_item_count);
            dap_list_t *l_list_tmp = l_list_out_items;
            int l_out_idx_tmp = 0; // current index of 'out' item
            //log_it(L_DEBUG,"We have %d outputs in new TX", l_item_count);
            while(l_list_tmp) {
                dap_chain_tx_out_t *l_out = l_list_tmp->data;
                if( ! l_out){
                    log_it(L_WARNING, "Output is NULL, continue check outputs...");
                    l_out_idx_tmp++;
                    continue;
                }
                if (l_out->header.type == TX_ITEM_TYPE_OUT_COND) {
                    l_list_tmp = l_list_tmp->next;
                    l_out_idx_tmp++;
                    continue;
                }
                if ( memcmp(&l_out->addr, a_addr_from, sizeof (*a_addr_from))==0 ){
                    list_used_item_t *l_item_back = DAP_NEW_Z(list_used_item_t);
                    l_item_back->tx_hash_fast = l_tx_new_hash;
                    l_item_back->num_idx_out = l_out_idx_tmp;
                    l_item_back->value = l_value_back;
                    l_list_used_out = dap_list_prepend(l_list_used_out, l_item_back);
                    log_it(L_DEBUG,"Found change back output, stored back in UTXO table");
                    break;
                 }
                l_list_tmp = l_list_tmp->next;
                l_out_idx_tmp++;
            }
            //log_it(L_DEBUG,"Checked all outputs");
            dap_list_free( l_list_out_items);
        }
        SUBTRACT_256_256(l_value_transfer, l_value_pack, &l_value_transfer);

        // Now produce datum
        dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx_new, l_tx_size);

        dap_chain_datum_tx_delete(l_tx_new);
        //dap_chain_ledger_tx_add( a_chain->ledger, l_tx);

        l_objs[i].key = dap_chain_hash_fast_to_str_new(&l_tx_new_hash);
        //continue;
        l_objs[i].value = (uint8_t *)l_datum;
        l_objs[i].value_len = dap_chain_datum_size(l_datum);
//        l_objs[i].value_len = l_tx_size + sizeof(l_datum->header);
        log_it(L_DEBUG, "Prepared obj with key %s (value_len = %"DAP_UINT64_FORMAT_U")",
               l_objs[i].key? l_objs[i].key :"NULL" , l_objs[i].value_len );

    }
    dap_list_free_full(l_list_used_out, free);

    char * l_gdb_group = dap_chain_net_get_gdb_group_mempool(a_chain);

    //return 0;
    if( dap_chain_global_db_gr_save(l_objs,a_tx_num,l_gdb_group) ) {
        log_it(L_NOTICE, "%zu transaction are placed in mempool", a_tx_num);
        DAP_DELETE(l_objs);
        DAP_DELETE(l_gdb_group);
        return 0;
    }else{
        log_it(L_ERROR, "Can't place %zu transactions  in mempool", a_tx_num);
        DAP_DELETE(l_objs);
        DAP_DELETE(l_gdb_group);
        return -4;
    }


}

dap_chain_datum_t *dap_chain_tx_create_cond_input(dap_chain_net_t * a_net, dap_chain_hash_fast_t *a_tx_prev_hash,
                                                  const dap_chain_addr_t* a_addr_to, dap_enc_key_t *a_key_tx_sign,
                                                  dap_chain_datum_tx_receipt_t * a_receipt)
{
    dap_ledger_t * l_ledger = a_net ? dap_chain_ledger_by_net_name( a_net->pub.name ) : NULL;
    if ( ! a_net || ! l_ledger || ! a_addr_to )
        return NULL;
    if ( ! dap_chain_addr_check_sum (a_addr_to) ){
        log_it(L_ERROR, "Wrong address_to checksum");
        return NULL;
    }   
    dap_chain_hash_fast_t *l_tx_final_hash = dap_chain_ledger_get_final_chain_tx_hash(l_ledger, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY, a_tx_prev_hash);
    if (!l_tx_final_hash) {
        log_it(L_WARNING, "Requested conditional transaction is already used out");
        return NULL;
    }
    if (dap_strcmp(a_net->pub.native_ticker, dap_chain_ledger_tx_get_token_ticker_by_hash(l_ledger, l_tx_final_hash))) {
        log_it(L_WARNING, "Pay for service should be only in native token ticker");
        return NULL;
    }
    dap_chain_datum_tx_t *l_tx_cond = dap_chain_ledger_tx_find_by_hash(l_ledger, l_tx_final_hash);
    int l_out_cond_idx = -1;
    dap_chain_tx_out_cond_t *l_out_cond = dap_chain_datum_tx_out_cond_get(l_tx_cond, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY, &l_out_cond_idx);
    if (!l_out_cond) {
        log_it(L_WARNING, "Requested conditioned transaction have no conditioned output");
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
        return NULL;
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    dap_chain_datum_tx_add_item(&l_tx, (byte_t*)a_receipt);
    // add 'in_cond' items
    if (dap_chain_datum_tx_add_in_cond_item(&l_tx, l_tx_final_hash, l_out_cond_idx, 0)) {
        dap_chain_datum_tx_delete(l_tx);
        log_it( L_ERROR, "Cant add tx cond input");
        return NULL;
    }
    // add 'out' item
    if (dap_chain_datum_tx_add_out_item(&l_tx, a_addr_to, a_receipt->receipt_info.value_datoshi) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        log_it( L_ERROR, "Cant add tx output");
        return NULL;
    }
    // add network fee
    if (l_net_fee_used) {
        if (dap_chain_datum_tx_add_out_item(&l_tx, &l_addr_fee, l_net_fee) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            log_it( L_ERROR, "Cant add tx output");
            return NULL;
        }
    }
    // add validator's fee
    if (!IS_ZERO_256(l_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, l_fee) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            log_it( L_ERROR, "Cant add tx output");
            return NULL;
        }
    }
    //add 'out_cond' item
    uint256_t l_new_val = {};
    uint256_t l_value_cond = l_out_cond->header.value;
    SUBTRACT_256_256(l_out_cond->header.value, l_value_send, &l_new_val);
    l_out_cond->header.value = l_new_val;       // Use old conditinal output to form the new one
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_out_cond);
    l_out_cond->header.value = l_value_cond;    // Restore original value
    // add 'sign' item
    if(dap_chain_datum_tx_add_sign_item(&l_tx, a_key_tx_sign) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        log_it( L_ERROR, "Can't add sign output");
        return NULL;
    }
    size_t l_tx_size = dap_chain_datum_tx_get_size( l_tx );
    dap_chain_datum_t *l_datum = dap_chain_datum_create( DAP_CHAIN_DATUM_TX, l_tx, l_tx_size );
    dap_chain_datum_tx_delete(l_tx);
    return l_datum;
}

dap_chain_hash_fast_t* dap_chain_mempool_tx_create_cond_input(dap_chain_net_t * a_net, dap_chain_hash_fast_t *a_tx_prev_hash,
                                                              const dap_chain_addr_t* a_addr_to, dap_enc_key_t *a_key_tx_sign,
                                                              dap_chain_datum_tx_receipt_t * a_receipt)
{
    dap_chain_datum_t *l_datum = dap_chain_tx_create_cond_input(a_net, a_tx_prev_hash, a_addr_to, a_key_tx_sign, a_receipt);
    dap_chain_hash_fast_t *l_key_hash = DAP_NEW_Z( dap_chain_hash_fast_t );
    dap_hash_fast(l_datum->data, l_datum->header.data_size, l_key_hash);

    char * l_key_str = dap_chain_hash_fast_to_str_new( l_key_hash );

    char * l_gdb_group = dap_chain_net_get_gdb_group_mempool_by_chain_type(a_net, CHAIN_TYPE_TX);

    if( dap_chain_global_db_gr_set( l_key_str, l_datum, dap_chain_datum_size(l_datum), l_gdb_group ) ) {
        log_it(L_NOTICE, "Transaction %s placed in mempool", l_key_str);

    DAP_DELETE(l_datum);
    }

    DAP_DELETE(l_gdb_group);
    DAP_DELETE(l_key_str);

    return l_key_hash;
}


/**
 * Make transfer transaction
 *
 * return dap_chain_datum_t, NULL if Error
 */
static dap_chain_datum_t* dap_chain_tx_create_cond(dap_chain_net_t *a_net,
        dap_enc_key_t *a_key_from, dap_pkey_t *a_key_cond,
        const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
        uint256_t a_value, uint256_t a_value_per_unit_max, dap_chain_net_srv_price_unit_uid_t a_unit,
        dap_chain_net_srv_uid_t a_srv_uid, uint256_t a_value_fee, const void *a_cond, size_t a_cond_size)
{
    dap_ledger_t * l_ledger = a_net ? dap_chain_ledger_by_net_name( a_net->pub.name ) : NULL;
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
    // where to take coins for service
    dap_chain_addr_t l_addr_from;
    dap_chain_addr_fill_from_key(&l_addr_from, a_key_from, a_net->pub.id);
    // list of transaction with 'out' items
    dap_list_t *l_list_used_out = dap_chain_ledger_get_list_tx_outs_with_val(l_ledger, a_token_ticker,
                                                                             &l_addr_from, l_value_need, &l_value_transfer);
    if(!l_list_used_out) {
        log_it( L_ERROR, "Nothing to tranfer (not enough funds)");
        return NULL;
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    // add 'in' items
    {
        uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
        assert(EQUAL_256(l_value_to_items, l_value_transfer));
        dap_list_free_full(l_list_used_out, free);
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
            if (dap_chain_datum_tx_add_out_item(&l_tx, &l_addr_fee, l_net_fee) == 1)
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
            if(dap_chain_datum_tx_add_out_item(&l_tx, &l_addr_from, l_value_back) != 1) {
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

    return l_datum;
}

/**
 * Make transfer transaction & insert to cache
 *
 * return 0 Ok, -2 not enough funds to transfer, -1 other Error
 */
dap_chain_hash_fast_t* dap_chain_mempool_tx_create_cond(dap_chain_net_t * a_net,
        dap_enc_key_t *a_key_from, dap_pkey_t *a_key_cond,
        const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
        uint256_t a_value, uint256_t a_value_per_unit_max, dap_chain_net_srv_price_unit_uid_t a_unit,
        dap_chain_net_srv_uid_t a_srv_uid, uint256_t a_value_fee, const void *a_cond, size_t a_cond_size)
{
    // Make transfer transaction
    dap_chain_datum_t *l_datum = dap_chain_tx_create_cond(a_net, a_key_from, a_key_cond,
                                                          a_token_ticker, a_value, a_value_per_unit_max,
                                                          a_unit, a_srv_uid, a_value_fee, a_cond, a_cond_size);

    if(!l_datum)
        return NULL;

    dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t*)&(l_datum->data);
    size_t l_tx_size = l_datum->header.data_size;//dap_chain_datum_tx_get_size( l_tx );

    dap_chain_hash_fast_t *l_key_hash = DAP_NEW_Z( dap_chain_hash_fast_t );
    dap_hash_fast( l_tx, l_tx_size, l_key_hash );
    //DAP_DELETE( l_tx );

    char * l_key_str = dap_chain_hash_fast_to_str_new( l_key_hash );
    dap_chain_t *l_chain = dap_chain_net_get_default_chain_by_chain_type(a_net, CHAIN_TYPE_TX);
    char *l_gdb_group = dap_chain_net_get_gdb_group_mempool(l_chain);

    if( dap_chain_global_db_gr_set( l_key_str, l_datum, dap_chain_datum_size(l_datum), l_gdb_group ) ) {
                log_it(L_NOTICE, "Transaction %s placed in mempool group %s", l_key_str, l_gdb_group);
    }

    DAP_DELETE(l_gdb_group);
    DAP_DELETE(l_key_str);

    return l_key_hash;
}

dap_chain_hash_fast_t *dap_chain_mempool_base_tx_create(dap_chain_t *a_chain, dap_chain_hash_fast_t *a_emission_hash,
                                                        dap_chain_id_t a_emission_chain_id, uint256_t a_emission_value, const char *a_ticker,
                                                        dap_chain_addr_t *a_addr_to, dap_cert_t **a_certs, size_t a_certs_count)
{
    char *l_gdb_group_mempool_base_tx = dap_chain_net_get_gdb_group_mempool(a_chain);
    // create first transaction (with tx_token)
    dap_chain_datum_tx_t *l_tx = DAP_NEW_Z_SIZE(dap_chain_datum_tx_t, sizeof(dap_chain_datum_tx_t));
    l_tx->header.ts_created = time(NULL);
    dap_chain_hash_fast_t l_tx_prev_hash = { 0 };

    // create items
    dap_chain_tx_token_t *l_tx_token = dap_chain_datum_tx_item_token_create(a_emission_chain_id, a_emission_hash, a_ticker);
    dap_chain_tx_in_t *l_in = dap_chain_datum_tx_item_in_create(&l_tx_prev_hash, 0);
    dap_chain_tx_out_t *l_out = dap_chain_datum_tx_item_out_create(a_addr_to, a_emission_value);

    // pack items to transaction
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_tx_token);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_in);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_out);

    if (a_certs) {
        // Sign all that we have with certs
        for(size_t i = 0; i < a_certs_count; i++) {
            if(dap_chain_datum_tx_add_sign_item(&l_tx, a_certs[i]->enc_key) < 0) {
                log_it(L_WARNING, "No private key for certificate '%s'", a_certs[i]->name);
                return NULL;
            }
        }
    }

    DAP_DEL_Z(l_tx_token);
    DAP_DEL_Z(l_in);
    DAP_DEL_Z(l_out);

    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);

    // Pack transaction into the datum
    dap_chain_datum_t * l_datum_tx = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, l_tx_size);
    size_t l_datum_tx_size = dap_chain_datum_size(l_datum_tx);
    DAP_DEL_Z(l_tx);
    // calc datum hash
    dap_chain_hash_fast_t *l_datum_tx_hash = DAP_NEW(dap_hash_fast_t);
    dap_hash_fast(l_datum_tx->data, l_tx_size, l_datum_tx_hash);
    char *l_tx_hash_str = dap_chain_hash_fast_to_str_new(l_datum_tx_hash);
    // Add to mempool tx token
    bool l_placed = dap_chain_global_db_gr_set(l_tx_hash_str, l_datum_tx,
                                               l_datum_tx_size, l_gdb_group_mempool_base_tx);
    DAP_DEL_Z(l_tx_hash_str);
    DAP_DELETE(l_datum_tx);
    if (!l_placed) {
        return NULL;
    }
    return l_datum_tx_hash;
}

dap_chain_datum_token_emission_t *dap_chain_mempool_emission_get(dap_chain_t *a_chain, const char *a_emission_hash_str)
{
    size_t l_emission_size;
    char *l_gdb_group = dap_chain_net_get_gdb_group_mempool(a_chain);
    dap_chain_datum_t *l_emission = (dap_chain_datum_t *)dap_chain_global_db_gr_get(
                                                    a_emission_hash_str, &l_emission_size, l_gdb_group);
    if (!l_emission) {
        char *l_emission_hash_str_from_base58 = dap_enc_base58_to_hex_str_from_str(a_emission_hash_str);
        l_emission = (dap_chain_datum_t *)dap_chain_global_db_gr_get(
                                    l_emission_hash_str_from_base58, &l_emission_size, l_gdb_group);
        DAP_DELETE(l_emission_hash_str_from_base58);
    }
    DAP_DELETE(l_gdb_group);
    if (!l_emission || l_emission->header.type_id != DAP_CHAIN_DATUM_TOKEN_EMISSION)
        return NULL;
    l_emission_size = l_emission_size - sizeof(l_emission->header);
    dap_chain_datum_token_emission_t *l_ret = dap_chain_datum_emission_read(l_emission->data, &l_emission_size);
    DAP_DELETE(l_emission);
    return l_ret;
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
    dap_chain_datum_token_t *l_token = dap_chain_ledger_token_ticker_check(l_net->pub.ledger, l_ticker);
    if (!l_token)
        return NULL;
    if (l_token->type != DAP_CHAIN_DATUM_TOKEN_TYPE_NATIVE_DECL)
        return NULL;
    /*int l_signs_valid = 0;
    dap_sign_t *l_ems_sign = (dap_sign_t *)(l_emission->tsd_n_signs + l_emission->data.type_auth.tsd_total_size);
    for (int i = 0; i < l_emission->data.type_auth.signs_count; i++) {
        uint32_t l_ems_pkey_size = l_ems_sign->header.sign_pkey_size;
        dap_sign_t *l_token_sign = (dap_sign_t *)(l_token->data_n_tsd + l_token->header_native_decl.tsd_total_size);
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
    uint8_t *a_request = DAP_NEW_SIZE(uint8_t, a_request_size);
    memcpy(a_request + shift_size, &(datum_mempool->version), sizeof(uint16_t));
    shift_size += sizeof(uint16_t);
    memcpy(a_request + shift_size, &(datum_mempool->datum_count), sizeof(uint16_t));
    shift_size += sizeof(uint16_t);
    for(int i = 0; i < datum_mempool->datum_count; i++) {
        size_t size_one = dap_chain_datum_size(datum_mempool->data[i]);
        memcpy(a_request + shift_size, &size_one, sizeof(uint16_t));
        shift_size += sizeof(uint16_t);
        memcpy(a_request + shift_size, datum_mempool->data[i], size_one);
        shift_size += size_one;
    }
    assert(shift_size == a_request_size);
    if(size)
        *size = a_request_size;
    return a_request;
}

dap_datum_mempool_t * dap_datum_mempool_deserialize(uint8_t *a_datum_mempool_ser, size_t a_datum_mempool_ser_size)
{
    size_t shift_size = 0;
    //uint8_t *a_datum_mempool_ser = DAP_NEW_Z_SIZE(uint8_t, datum_mempool_size / 2 + 1);
    //datum_mempool_size = hex2bin(a_datum_mempool_ser, datum_mempool_str_in, datum_mempool_size) / 2;
    dap_datum_mempool_t *datum_mempool = DAP_NEW_Z(dap_datum_mempool_t);
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
static char* calc_datum_hash(const char *datum_str, size_t datum_size)
{
    dap_chain_hash_fast_t a_hash;
    dap_hash_fast( datum_str, datum_size, &a_hash);
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
            DAP_DEL_Z(a_http_simple->reply);

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
    dap_enc_key_t *key = dap_enc_ks_find_http(cl_st->http_client);
    //dap_enc_key_serialize_t *key_ser = dap_enc_key_serialize(key_tmp);
    //dap_enc_key_t *key = dap_enc_key_deserialize(key_ser, sizeof(dap_enc_key_serialize_t));

    // read header
    dap_http_header_t *hdr_session_close_id =
            (cl_st->http_client) ? dap_http_header_find(cl_st->http_client->in_headers, "SessionCloseAfterRequest") : NULL;
    dap_http_header_t *hdr_key_id =
            (hdr_session_close_id && cl_st->http_client) ? dap_http_header_find(cl_st->http_client->in_headers, "KeyID") : NULL;

    enc_http_delegate_t *dg = enc_http_request_decode(cl_st);
    if(dg) {
        char *suburl = dg->url_path;
        char *request_str = dg->request_str;
        int request_size = (int) dg->request_size;
        //printf("!!***!!! chain_mempool_proc arg=%d suburl=%s str=%s len=%d\n", arg, suburl, request_str, request_size);
        if(request_str && request_size > 1) {
            //  find what to do
            uint8_t action = DAP_DATUM_MEMPOOL_NONE; //*(uint8_t*) request_str;
            if(dg->url_path_size > 0) {
                if(!strcmp(suburl, "add"))
                    action = DAP_DATUM_MEMPOOL_ADD;
                else if(!strcmp(suburl, "check"))
                    action = DAP_DATUM_MEMPOOL_CHECK;
                else if(!strcmp(suburl, "del"))
                    action = DAP_DATUM_MEMPOOL_DEL;
            }
            dap_datum_mempool_t *datum_mempool =
                    (action != DAP_DATUM_MEMPOOL_NONE) ?
                            dap_datum_mempool_deserialize((uint8_t*) request_str, (size_t) request_size) : NULL;
            if(datum_mempool){
                dap_datum_mempool_free(datum_mempool);
                char *a_key = calc_datum_hash(request_str, (size_t) request_size);
                switch (action)
                {
                case DAP_DATUM_MEMPOOL_ADD: // add datum in base
                    //a_value = DAP_NEW_Z_SIZE(char, request_size * 2);
                    //bin2hex((char*) a_value, (const unsigned char*) request_str, request_size);
                    if ( dap_chain_global_db_gr_set(a_key, request_str, request_size,
                            dap_config_get_item_str_default(g_config, "mempool", "gdb_group", "datum-pool"))) {
                        *return_code = Http_Status_OK;
                    }
                    log_it(L_INFO, "Insert hash: key=%s result:%s", a_key,
                            (*return_code == Http_Status_OK) ? "OK" : "False!");
                    DAP_DEL_Z(a_key);
                    break;

                case DAP_DATUM_MEMPOOL_CHECK: // check datum in base

                    strcpy(cl_st->reply_mime, "text/text");
                    char *str = (char*) dap_chain_global_db_gr_get( dap_strdup(a_key) , NULL,
                            dap_config_get_item_str_default(g_config, "mempool", "gdb_group", "datum-pool"));
                    if(str) {
                        dg->response = strdup("1");
                        DAP_DEL_Z(str);
                        log_it(L_INFO, "Check hash: key=%s result: Present", a_key);
                    }
                    else {
                        dg->response = strdup("0");
                        log_it(L_INFO, "Check hash: key=%s result: Absent", a_key);
                    }
                    dg->response_size = strlen(dg->response);
                    *return_code = Http_Status_OK;
                    enc_http_reply_encode_new(cl_st, key, dg);
                    break;

                case DAP_DATUM_MEMPOOL_DEL: // delete datum in base
                    strcpy(cl_st->reply_mime, "text/text");
                    if(dap_chain_global_db_gr_del( a_key,
                            dap_config_get_item_str_default(g_config, "mempool", "gdb_group", "datum-pool"))) {
                        dg->response = strdup("1");

                        log_it(L_INFO, "Delete hash: key=%s result: Ok", a_key);
                    }
                    else {
                        dg->response = strdup("0");
                        log_it(L_INFO, "Delete hash: key=%s result: False!", a_key);
                    }
                    *return_code = Http_Status_OK;
                    enc_http_reply_encode_new(cl_st, key, dg);
                    break;

                default: // unsupported command
                    log_it(L_INFO, "Unknown request=%s! key=%s", (suburl) ? suburl : "-", a_key);
                    DAP_DEL_Z(a_key);
                    enc_http_delegate_delete(dg);
                    if(key)
                        dap_enc_key_delete(key);
                    return;
                }
                DAP_DEL_Z(a_key);
            } else  *return_code = Http_Status_BadRequest;
        }
        else    *return_code = Http_Status_BadRequest;

        enc_http_delegate_delete(dg);
    }
    else    *return_code = Http_Status_Unauthorized;

    if(hdr_session_close_id && hdr_session_close_id->value && !strcmp(hdr_session_close_id->value, "yes")) {
        // close session
        if(hdr_key_id && hdr_key_id->value) {
            dap_enc_ks_delete(hdr_key_id->value);
        }
    }
}

/**
 * @brief chain_mempool_add_proc
 * @param sh HTTP server instance
 * @param url URL string
 */
void dap_chain_mempool_add_proc(dap_http_t * a_http_server, const char * a_url)
{
    dap_http_simple_proc_add(a_http_server, a_url, 4096, chain_mempool_proc);
}

void dap_chain_mempool_filter(dap_chain_t *a_chain, int *a_removed){
    int l_removed = 0;
    if (!a_chain) {
        if (!a_removed)
            *a_removed = l_removed;
        return;
    }
    char * l_gdb_group = dap_chain_net_get_gdb_group_mempool(a_chain);
    size_t l_objs_size = 0;
    dap_time_t l_cut_off_time = dap_time_now() - 2592000; // 2592000 sec = 30 days
    char l_cut_off_time_str[80] = {'\0'};
    dap_time_to_str_rfc822(&l_cut_off_time_str, 80, l_cut_off_time);
    dap_global_db_obj_t * l_objs = dap_chain_global_db_gr_load(l_gdb_group, &l_objs_size);
    for (size_t i = 0; i < l_objs_size; i++) {
        dap_chain_datum_t *l_datum = (dap_chain_datum_t*)l_objs[i].value;
        if (!l_datum) {
            l_removed++;
            log_it(L_NOTICE, "Removed datum from mempool with \"%s\" key group %s: empty (possibly trash) value", l_objs[i].key, l_gdb_group);
            dap_chain_global_db_gr_del(l_objs[i].key, l_gdb_group);
            continue;
        }
        size_t l_datum_size = dap_chain_datum_size(l_datum);
        //Filter data size
        if (l_datum_size != l_objs[i].value_len) {
            l_removed++;
            log_it(L_NOTICE, "Removed datum from mempool with \"%s\" key group %s. The size of the datum defined by the "
                             "function and the size specified in the record do not match.", l_objs[i].key, l_gdb_group);
            dap_chain_global_db_gr_del(l_objs[i].key, l_gdb_group);
            continue;
        }
        //Filter hash
        dap_hash_fast_t l_hash_content = {0};
        dap_hash_fast(l_datum->data, l_datum->header.data_size, &l_hash_content);
        char *l_hash_content_str = dap_hash_fast_to_str_new(&l_hash_content);
        if (dap_strcmp(l_hash_content_str, l_objs[i].key) != 0) {
            l_removed++;
            DAP_DELETE(l_hash_content_str);
            log_it(L_NOTICE, "Removed datum from mempool with \"%s\" key group %s. The hash of the contents of the "
                             "datum does not match the key.", l_objs[i].key, l_gdb_group);
            dap_chain_global_db_gr_del(l_objs[i].key, l_gdb_group);
            continue;
        }
        DAP_DELETE(l_hash_content_str);
        //Filter time
        if (l_datum->header.ts_create < l_cut_off_time) {
            l_removed++;
            log_it(L_NOTICE, "Removed datum from mempool with \"%s\" key group %s. The datum in the mempool was "
                             "created before the %s.", l_objs[i].key, l_gdb_group, l_cut_off_time_str);
            dap_chain_global_db_gr_del(l_objs[i].key, l_gdb_group);
        }
    }
    dap_chain_global_db_objs_delete(l_objs, l_objs_size);
    log_it(L_NOTICE, "Filter removed: %i records.", l_removed);
    DAP_DELETE(l_gdb_group);
}
