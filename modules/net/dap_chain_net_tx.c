/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Cellframe Network https://cellframe.net
 * Copyright  (c) 2022
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

#include <string.h>
#include "dap_chain_net_tx.h"
#include "dap_chain_cell.h"
#include "dap_chain_common.h"
#include "dap_chain_block_cache.h"
#include "dap_chain_ledger.h"
#include "dap_chain_datum_tx_in_cond.h"
#include "dap_chain_datum_tx_in_reward.h"
#include "dap_chain_tx.h"
#include "dap_json.h"
#include "dap_list.h"
#include "dap_chain_type_blocks.h"
#include "dap_chain_wallet_shared.h"
#include "dap_chain_datum_tx_receipt.h"
#include "dap_chain_wallet.h"
#include "dap_chain_wallet_cache.h"
#include "dap_chain_datum_tx_voting.h"
#include "json.h"
#include "dap_chain_srv.h"
#include "dap_chain_net_srv.h"
#include "dap_enc_base64.h"

#define LOG_TAG "dap_chain_net_tx"
const dap_chain_addr_t c_dap_chain_addr_blank_1 = {0};

typedef struct cond_all_with_spends_by_srv_uid_arg{
    dap_chain_datum_tx_spends_items_t * ret;
    dap_chain_srv_uid_t srv_uid;
    dap_time_t time_from;
    dap_time_t time_to;
} cond_all_with_spends_by_srv_uid_arg_t;

typedef struct cond_all_by_srv_uid_arg{
    dap_list_t * ret;
    dap_chain_srv_uid_t srv_uid;
    dap_time_t time_from;
    dap_time_t time_to;
} cond_all_by_srv_uid_arg_t;

dap_tx_creator_tokenizer_t *s_values_need = NULL;

static int s_find_add_token_val (const char *a_token, uint256_t a_value, int(*operation)(uint256_t, uint256_t, uint256_t *));

static void s_tx_cond_all_with_spends_by_srv_uid_callback(dap_chain_net_t* a_net, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash, void *a_arg)
{
    cond_all_with_spends_by_srv_uid_arg_t *l_arg = (cond_all_with_spends_by_srv_uid_arg_t*)a_arg;
    dap_chain_datum_tx_spends_items_t *l_ret = l_arg->ret;

    dap_return_if_pass(( l_arg->time_from && a_tx->header.ts_created < l_arg->time_from )
                    || ( l_arg->time_to && a_tx->header.ts_created > l_arg->time_to ));
    byte_t *l_item; size_t l_size;
    TX_ITEM_ITER_TX(l_item, l_size, a_tx) {
        switch (*l_item) {
        case TX_ITEM_TYPE_IN_COND: {
            dap_chain_tx_in_cond_t *l_tx_in_cond = (dap_chain_tx_in_cond_t*)l_item;
            dap_chain_datum_tx_spends_item_t *l_spends = NULL;
            dap_hash_fast_t l_prev_hash = l_tx_in_cond->header.tx_prev_hash;
            HASH_FIND(hh, l_ret->tx_outs, &l_prev_hash, sizeof(l_prev_hash), l_spends);
            if (l_spends) {
                dap_chain_datum_tx_spends_item_t *l_in = DAP_NEW_Z(dap_chain_datum_tx_spends_item_t);
                *l_in = (dap_chain_datum_tx_spends_item_t) {
                    .tx = a_tx,
                    .tx_hash = *a_tx_hash,
                    .in_cond = l_tx_in_cond
                };
                HASH_ADD(hh, l_ret->tx_ins, tx_hash, sizeof(dap_chain_hash_fast_t), l_in);
                l_spends->tx_next = a_tx;
            }
        } break;
        case TX_ITEM_TYPE_OUT_COND: {
            dap_chain_tx_out_cond_t *l_tx_out_cond = (dap_chain_tx_out_cond_t*)l_item;
            if (l_tx_out_cond->header.srv_uid.uint64 == l_arg->srv_uid.uint64) {
                dap_chain_datum_tx_spends_item_t *l_out = DAP_NEW_Z(dap_chain_datum_tx_spends_item_t);
                *l_out = (dap_chain_datum_tx_spends_item_t) {
                    .tx = a_tx,
                    .tx_hash = *a_tx_hash,
                    .out_cond = l_tx_out_cond
                };
                HASH_ADD(hh, l_ret->tx_outs, tx_hash, sizeof(dap_chain_hash_fast_t), l_out);
                // ??? TODO?
            }
        } break;
        default:
            break;
        }
    }
}

/**
 * @brief For now it returns all COND_IN transactions
 * @param a_net
 * @param a_srv_uid
 * @param a_search_type
 * @return Hash lists of dap_chain_datum_tx_item_t with conditional transaction and it spending if present
 */
dap_chain_datum_tx_spends_items_t * dap_chain_net_get_tx_cond_all_with_spends_by_srv_uid(dap_chain_net_t * a_net, const dap_chain_srv_uid_t a_srv_uid,
                                                      const dap_time_t a_time_from, const dap_time_t a_time_to,
                                                     const dap_chain_net_tx_search_type_t a_search_type)
{
    cond_all_with_spends_by_srv_uid_arg_t *l_ret = DAP_NEW_Z(cond_all_with_spends_by_srv_uid_arg_t);
    if (!l_ret) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }

    l_ret->ret = DAP_NEW_Z(dap_chain_datum_tx_spends_items_t);
    if (!l_ret->ret) {
        DAP_DEL_Z(l_ret);
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    l_ret->srv_uid = a_srv_uid;
    l_ret->time_from = a_time_from;
    l_ret->time_to = a_time_to;

    dap_chain_net_get_tx_all(a_net, a_search_type, s_tx_cond_all_with_spends_by_srv_uid_callback, l_ret);

    return l_ret->ret;
}

/**
 * @brief dap_chain_datum_tx_spends_items_free
 * @param a_items
 */
void dap_chain_datum_tx_spends_items_free(dap_chain_datum_tx_spends_items_t * a_items)
{
    assert(a_items);
    dap_chain_datum_tx_spends_item_free(a_items->tx_ins);
    dap_chain_datum_tx_spends_item_free(a_items->tx_outs);
    DAP_DELETE(a_items);
}

/**
 * @brief dap_chain_datum_tx_spends_item_free
 * @param a_items
 */
void dap_chain_datum_tx_spends_item_free(dap_chain_datum_tx_spends_item_t * a_items)
{
    dap_chain_datum_tx_spends_item_t * l_item, *l_tmp;
    HASH_ITER(hh,a_items,l_item,l_tmp){
        DAP_DELETE(l_item->tx);
        HASH_DELETE(hh,a_items, l_item);
        DAP_DELETE(l_item);
    }
}

/**
 * @brief dap_chain_net_get_tx_all
 * @param a_net
 * @param a_search_type
 * @param a_tx_callback
 * @param a_arg
 */
void dap_chain_net_get_tx_all(dap_chain_net_t * a_net, dap_chain_net_tx_search_type_t a_search_type ,dap_chain_net_tx_hash_callback_t a_tx_callback, void * a_arg)
{
    assert(a_tx_callback);
    switch (a_search_type) {
        case TX_SEARCH_TYPE_NET_UNSPENT:
        case TX_SEARCH_TYPE_NET:
        case TX_SEARCH_TYPE_LOCAL:{
            dap_ledger_datum_iter_t *l_iter = dap_ledger_datum_iter_create(a_net);
            if ( l_iter && dap_ledger_datum_iter_get_first(l_iter) ) {
                while(l_iter->cur) {
                    if (a_search_type != TX_SEARCH_TYPE_NET_UNSPENT ||
                        (a_search_type == TX_SEARCH_TYPE_NET_UNSPENT && l_iter->is_unspent)){
                        a_tx_callback(a_net, l_iter->cur, &l_iter->cur_hash, a_arg);
                    }
                    dap_ledger_datum_iter_get_next(l_iter);
                }
                dap_ledger_datum_iter_get_next(l_iter);
            }
            dap_ledger_datum_iter_delete(l_iter);
        break;
        }
        case TX_SEARCH_TYPE_CELL_SPENT:
        case TX_SEARCH_TYPE_CELL_UNSPENT:
        case TX_SEARCH_TYPE_CELL:
            break;
        case TX_SEARCH_TYPE_BLOCKCHAIN:{
            // pass all chains
            for ( dap_chain_t * l_chain = a_net->pub.chains; l_chain; l_chain = l_chain->next){
//                dap_chain_cell_t * l_cell, *l_cell_tmp;
//                // Go through all cells
//                HASH_ITER(hh,l_chain->cells,l_cell, l_cell_tmp){
                dap_chain_datum_iter_t * l_datum_iter = l_chain->callback_datum_iter_create(l_chain);
                l_chain->callback_datum_iter_get_first(l_datum_iter);

                    // Check atoms in chain
                while(l_datum_iter->cur) {
                    dap_chain_datum_t *l_datum = l_datum_iter->cur;
                    // transaction
                    dap_chain_datum_tx_t *l_tx = NULL;
                    // Check if its transaction
                    if (l_datum && (l_datum->header.type_id == DAP_CHAIN_DATUM_TX)) {
                        l_tx = (dap_chain_datum_tx_t *) l_datum->data;
                    }

                    // If found TX
                    if ( l_tx ) {
                        a_tx_callback(a_net, l_tx, l_datum_iter->cur_hash, a_arg);
                    }

                    // go to next datum
                    l_chain->callback_datum_iter_get_next(l_datum_iter);
                }
                l_chain->callback_datum_iter_delete(l_datum_iter);
//                }
            }
        } break;
    }
}

/**
 * @brief The get_tx_cond_all_from_tx struct
 */
struct get_tx_cond_all_from_tx
{
    dap_list_t * ret;
    dap_hash_fast_t * tx_begin_hash;
    dap_chain_datum_tx_t * tx_last;
    dap_hash_fast_t tx_last_hash;
    int tx_last_cond_idx;
    dap_chain_srv_uid_t srv_uid;
};

/**
 * @brief s_get_tx_cond_all_from_tx_callback
 * @param a_net
 * @param a_tx
 * @param a_arg
 */
static void s_get_tx_cond_chain_callback(dap_chain_net_t* a_net, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash, void *a_arg)
{
    struct get_tx_cond_all_from_tx * l_args = (struct get_tx_cond_all_from_tx* ) a_arg;
    if( l_args->ret ){
        int l_item_idx = 0;
        byte_t *l_tx_item;
        dap_hash_fast_t * l_tx_hash = a_tx_hash;
        // Get items from transaction
        while ((l_tx_item = dap_chain_datum_tx_item_get(a_tx, &l_item_idx, NULL, TX_ITEM_TYPE_IN_COND , NULL)) != NULL){
            dap_chain_tx_in_cond_t * l_in_cond = (dap_chain_tx_in_cond_t *) l_tx_item;
            if(dap_hash_fast_compare(&l_in_cond->header.tx_prev_hash, &l_args->tx_last_hash) &&
                    (uint32_t)l_args->tx_last_cond_idx == l_in_cond->header.tx_out_prev_idx ){ // Found output
                // We're the next tx in tx cond chain

                l_args->ret = dap_list_append(l_args->ret, a_tx);
                // Check cond output and update tx last hash and index
                dap_chain_tx_out_cond_t * l_out_cond = NULL;
                int l_out_item_idx = 0;
                if ((l_out_cond = dap_chain_datum_tx_out_cond_get(a_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE, &l_out_item_idx)) &&
                        l_out_cond->header.srv_uid.uint64 == l_args->srv_uid.uint64) { // We found output with target service uuid
                    l_args->tx_last = a_tx; // Record current transaction as the last in tx chain
                    memcpy(&l_args->tx_last_hash, l_tx_hash, sizeof(*l_tx_hash)); // Record current hash
                    l_args->tx_last_cond_idx = l_out_item_idx;
                }
                break;
            }
            l_item_idx++;
        }
    }else if(a_tx){
        dap_hash_fast_t * l_tx_hash = a_tx_hash;
        if (!l_tx_hash) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            return;
        }
        if (dap_hash_fast_compare(l_tx_hash,l_args->tx_begin_hash)) {
            // Found condition
            int l_item_idx = 0;

            // Get items from transaction
            dap_chain_tx_out_cond_t * l_out_cond = NULL;
            while ((l_out_cond = dap_chain_datum_tx_out_cond_get(a_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE, &l_item_idx))){
                if ( l_out_cond->header.srv_uid.uint64 == l_args->srv_uid.uint64 ){ // We found output with target service uuid
                    l_args->tx_last = a_tx; // Record current transaction as the last in tx chain
                    l_args->tx_last_hash = *l_tx_hash;
                    l_args->tx_last_cond_idx = l_item_idx;
                    l_args->ret = dap_list_append(NULL, a_tx);
                    break;
                }
            }
        }
    }
}

/**
 * @brief Return spends chain for conditioned transaction since beginning one
 * @param a_net Network where to search for
 * @param l_tx_hash TX hash of the Tx chain beginning
 * @param a_srv_uid Service UID from witch cond output the chain begin
 * @return List of conditioned transactions followin each other one by one as they do as spends
 */
dap_list_t * dap_chain_net_get_tx_cond_chain(dap_chain_net_t * a_net, dap_hash_fast_t * a_tx_hash, dap_chain_srv_uid_t a_srv_uid)
{
    struct get_tx_cond_all_from_tx * l_args = DAP_NEW_Z(struct get_tx_cond_all_from_tx);
    if (!l_args) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    l_args->tx_begin_hash = a_tx_hash;
    l_args->srv_uid = a_srv_uid;
    dap_chain_net_get_tx_all(a_net,TX_SEARCH_TYPE_NET, s_get_tx_cond_chain_callback, l_args);
    dap_list_t * l_ret = l_args->ret;
    DAP_DELETE(l_args);
    return l_ret;
}

/**
 * @brief The get_tx_cond_all_for_addr struct
 */
struct get_tx_cond_all_for_addr
{
    dap_list_t * ret;
    dap_chain_tx_t * tx_all_hh; // Transactions hash table for target address
    const dap_chain_addr_t * addr;
    dap_chain_srv_uid_t srv_uid;
};

/**
 * @brief s_get_tx_cond_all_for_addr_callback
 * @param a_net
 * @param a_tx
 * @param a_arg
 */
static void s_get_tx_cond_all_for_addr_callback(dap_chain_net_t* a_net, dap_chain_datum_tx_t *a_datum_tx, dap_hash_fast_t *a_hash, void *a_arg)
{
    UNUSED(a_net);
    UNUSED(a_hash);
    struct get_tx_cond_all_for_addr * l_args = (struct get_tx_cond_all_for_addr* ) a_arg;

    bool l_tx_for_addr = false; // TX with output related with our address
    bool l_tx_from_addr = false; // TX with input that take assets from our address
    //const char *l_tx_from_addr_token = NULL;
    bool l_tx_collected = false;  // We already collected this TX in return list
    byte_t *l_tx_item = NULL; size_t l_size = 0; int l_idx = 0;
    // Get in items to detect is in or in_cond from target address
    TX_ITEM_ITER_TX(l_tx_item, l_size, a_datum_tx) {
        switch (*l_tx_item) {
        case TX_ITEM_TYPE_IN: {
            dap_chain_tx_in_t * l_in = (dap_chain_tx_in_t *) l_tx_item;
            if( l_tx_from_addr) // Already detected thats spends from addr
                break;
//                dap_chain_tx_t * l_tx = dap_chain_tx_hh_find( l_args->tx_all_hh, &l_in->header.tx_prev_hash);
            if( dap_chain_tx_hh_find( l_args->tx_all_hh, &l_in->header.tx_prev_hash) ){ // Its input thats closing output for target address - we note it
                l_tx_from_addr = true;
                //l_tx_from_addr_token = dap_ledger_tx_get_token_ticker_by_hash(a_net->pub.ledger, &l_tx->hash);
            }
        } break;
        case TX_ITEM_TYPE_IN_COND: {
            if(l_tx_collected) // Already collected
                break;
            dap_chain_tx_in_cond_t * l_in_cond = (dap_chain_tx_in_cond_t *) l_tx_item;
//                dap_chain_tx_t * l_tx = dap_chain_tx_hh_find( l_args->tx_all_hh, &l_in_cond->header.tx_prev_hash);
            if( dap_chain_tx_hh_find( l_args->tx_all_hh, &l_in_cond->header.tx_prev_hash) ){ // Its input thats closing conditioned tx related with target address, collect it
                //dap_chain_tx_t *l_tx_add = dap_chain_tx_wrap_packed(a_datum_tx);
                l_args->ret = dap_list_append(l_args->ret, a_datum_tx);
                l_tx_collected = true;
            }
        } break;
        }
    }
//dap_chain_datum_tx_out_cond_get(a_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE, &l_out_item_idx)
    // Get out items from transaction
    TX_ITEM_ITER_TX(l_tx_item, l_size, a_datum_tx) {
        switch (*l_tx_item) {
        case TX_ITEM_TYPE_OUT: {
            if(l_tx_for_addr) // Its already added
                break;
            dap_chain_tx_out_t * l_out = (dap_chain_tx_out_t*) l_tx_item;
            if ( memcmp(&l_out->addr, l_args->addr, sizeof(*l_args->addr)) == 0){ // Its our address tx
                dap_chain_tx_t * l_tx = dap_chain_tx_wrap_packed(a_datum_tx);
                dap_chain_tx_hh_add(&l_args->tx_all_hh, l_tx);
                l_tx_for_addr = true;
            }
        } break;
        case TX_ITEM_TYPE_OUT_EXT:{
            if(l_tx_for_addr) // Its already added
                break;
            dap_chain_tx_out_ext_t * l_out = (dap_chain_tx_out_ext_t*) l_tx_item;
            if ( memcmp(&l_out->addr, l_args->addr, sizeof(*l_args->addr)) == 0){ // Its our address tx
                dap_chain_tx_t * l_tx = dap_chain_tx_wrap_packed(a_datum_tx);
                dap_chain_tx_hh_add(&l_args->tx_all_hh, l_tx);
                l_tx_for_addr = true;
            }
        } break;
        case TX_ITEM_TYPE_OUT_STD: {
            if (l_tx_for_addr) // Its already added
                break;
            dap_chain_tx_out_std_t *l_out = (dap_chain_tx_out_std_t *)l_tx_item;
            if (memcmp(&l_out->addr, l_args->addr, sizeof(*l_args->addr)) == 0) { // Its our address tx
                dap_chain_tx_t *l_tx = dap_chain_tx_wrap_packed(a_datum_tx);
                dap_chain_tx_hh_add(&l_args->tx_all_hh, l_tx);
                l_tx_for_addr = true;
            }
        } break;
        case TX_ITEM_TYPE_OUT_COND:{
            dap_chain_tx_out_cond_t * l_out_cond = (dap_chain_tx_out_cond_t*) l_tx_item;
            if(l_tx_collected) // Already collected for return list
                break;

            // If this output spends monies from our address
            if(l_tx_from_addr && l_out_cond->header.srv_uid.uint64 == l_args->srv_uid.uint64){
                //dap_chain_tx_t *l_tx_add = dap_chain_tx_wrap_packed(a_datum_tx);
                l_args->ret = dap_list_append(l_args->ret, a_datum_tx);
                l_tx_collected = true;
            }
        } break;
    }
    }

}

/**
 * @brief Compose list of all cond transactions with target srv_uid for specified address
 * @param a_net
 * @param a_addr
 * @param a_srv_uid
 * @return List of dap_chain_tx_t (don't forget to free it)
 */
dap_list_t * dap_chain_net_get_tx_cond_all_for_addr(dap_chain_net_t * a_net, dap_chain_addr_t * a_addr, dap_chain_srv_uid_t a_srv_uid)
{
    struct get_tx_cond_all_for_addr * l_args = DAP_NEW_Z(struct get_tx_cond_all_for_addr);
    if (!l_args) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    l_args->addr = a_addr;
    l_args->srv_uid = a_srv_uid;
    dap_chain_net_get_tx_all(a_net,TX_SEARCH_TYPE_NET,s_get_tx_cond_all_for_addr_callback, l_args);
    dap_chain_tx_hh_free(l_args->tx_all_hh);
    dap_list_t * l_ret = l_args->ret;
    DAP_DELETE(l_args);
    return l_ret;
}

static void s_tx_cond_all_by_srv_uid_callback(UNUSED_ARG dap_chain_net_t* a_net, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash, void *a_arg)
{
    cond_all_by_srv_uid_arg_t *l_ret = (cond_all_by_srv_uid_arg_t*)a_arg;

    if (( l_ret->time_from && a_tx->header.ts_created < l_ret->time_from )
        || ( l_ret->time_to && a_tx->header.ts_created > l_ret->time_to ))
        return;

    byte_t *item; size_t l_size;
    dap_chain_datum_tx_cond_list_item_t *l_item = (dap_chain_datum_tx_cond_list_item_t*) DAP_NEW_Z(dap_chain_datum_tx_cond_list_item_t);
    TX_ITEM_ITER_TX(item, l_size, a_tx) {
        if ( *item == TX_ITEM_TYPE_OUT_COND &&
                l_ret->srv_uid.uint64 == ((dap_chain_tx_out_cond_t*)item)->header.srv_uid.uint64 ) {
            l_item->hash = *a_tx_hash;
            l_item->tx = a_tx;
            l_ret->ret = dap_list_append(l_ret->ret, l_item);
        }
    }
}

/**
 * @brief dap_chain_net_get_tx_cond_all_by_srv_uid
 * @param a_net
 * @param a_srv_uid
 * @param a_search_type
 * @return
 */
dap_list_t * dap_chain_net_get_tx_cond_all_by_srv_uid(dap_chain_net_t * a_net, const dap_chain_srv_uid_t a_srv_uid,
                                                      const dap_time_t a_time_from, const dap_time_t a_time_to,
                                                     const dap_chain_net_tx_search_type_t a_search_type)
{
    cond_all_by_srv_uid_arg_t l_ret = {};

    l_ret.srv_uid = a_srv_uid;
    l_ret.time_from = a_time_from;
    l_ret.time_to = a_time_to;

    dap_chain_net_get_tx_all(a_net, a_search_type, s_tx_cond_all_by_srv_uid_callback, &l_ret);

    return l_ret.ret;
}

/**
 * @brief dap_chain_net_tx_get_by_hash
 * @param a_net
 * @param a_tx_hash
 * @param a_search_type
 * @return
 */
dap_chain_datum_tx_t *dap_chain_net_get_tx_by_hash(dap_chain_net_t *a_net, dap_chain_hash_fast_t *a_tx_hash,
                                                   dap_chain_net_tx_search_type_t a_search_type)
{
    dap_ledger_t *l_ledger = a_net->pub.ledger;
    switch (a_search_type) {
    case TX_SEARCH_TYPE_NET:
    case TX_SEARCH_TYPE_LOCAL:
        return dap_ledger_tx_find_by_hash(l_ledger, a_tx_hash);
    case TX_SEARCH_TYPE_NET_UNSPENT:
        return dap_ledger_tx_unspent_find_by_hash(l_ledger, a_tx_hash);
    case TX_SEARCH_TYPE_CELL:
    case TX_SEARCH_TYPE_CELL_SPENT:
    case TX_SEARCH_TYPE_CELL_UNSPENT:
        /* Will be implemented soon */
        break;
    case TX_SEARCH_TYPE_BLOCKCHAIN:
        // pass all chains
        for (dap_chain_t * l_chain = a_net->pub.chains; l_chain; l_chain = l_chain->next) {
            if (!l_chain->callback_datum_find_by_hash)
                return NULL;
            // try to find transaction in chain ( inside shard )
            int l_ret_code;
            dap_chain_datum_t *l_datum = l_chain->callback_datum_find_by_hash(l_chain, a_tx_hash, NULL, &l_ret_code);
            if (!l_datum || l_datum->header.type_id != DAP_CHAIN_DATUM_TX)
                continue;
            return (dap_chain_datum_tx_t *)l_datum->data;
        }
    default: break;
    }
    return NULL;
}

bool dap_chain_net_tx_get_fee(dap_chain_net_id_t a_net_id, uint256_t *a_value, dap_chain_addr_t *a_addr)
{
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_net_id);
    if (!l_net){
        log_it(L_WARNING, "Can't find net with id 0x%016"DAP_UINT64_FORMAT_x"", a_net_id.uint64);
        return false;
    }
    if (IS_ZERO_256(l_net->pub.fee_value))
        return false;
    if (a_value)
        *a_value = l_net->pub.fee_value;
    if (a_addr)
        *a_addr = l_net->pub.fee_addr;
    return true;
}

bool dap_chain_net_tx_set_fee(dap_chain_net_id_t a_net_id, uint256_t a_value, dap_chain_addr_t a_addr)
{
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_net_id);
    if (!l_net){
        log_it(L_WARNING, "Can't find net with id 0x%016"DAP_UINT64_FORMAT_x"", a_net_id.uint64);
        return false;
    }
    l_net->pub.fee_value = a_value;
    l_net->pub.fee_addr = a_addr;

    return true;
}

static const char* s_json_get_text(dap_json_t *a_json, const char *a_key)
{
    if(!a_json || !a_key)
        return NULL;
    
    return dap_json_object_get_string(a_json, a_key);
}

static bool s_json_get_int64_uint64(dap_json_t *a_json, const char *a_key, void *a_out, bool a_is_uint64)
{
    if(!a_json || !a_key || !a_out)
        return false;
    
    if(a_is_uint64) {
        *(uint64_t*)a_out = dap_json_object_get_uint64(a_json, a_key);
    } else {
        *(int64_t*)a_out = dap_json_object_get_int64(a_json, a_key);
    }
    return true;
}

static bool s_json_get_unit(dap_json_t *a_json, const char *a_key, dap_chain_net_srv_price_unit_uid_t *a_out)
{
    const char *l_unit_str = s_json_get_text(a_json, a_key);
    if(!l_unit_str || !a_out)
        return false;
    dap_chain_net_srv_price_unit_uid_t l_unit = dap_chain_net_srv_price_unit_uid_from_str(l_unit_str);
    if(l_unit.enm == SERV_UNIT_UNDEFINED)
        return false;
    a_out->enm = l_unit.enm;
    return true;
}

static bool s_json_get_uint256(dap_json_t *a_json, const char *a_key, uint256_t *a_out)
{
    const char *l_uint256_str = s_json_get_text(a_json, a_key);
    if(!a_out || !l_uint256_str)
        return false;
    uint256_t l_value = dap_chain_balance_scan(l_uint256_str);
    if(!IS_ZERO_256(l_value)) {
        memcpy(a_out, &l_value, sizeof(uint256_t));
        return true;
    }
    return false;
}

// service names: srv_stake, srv_vpn, srv_xchange
static bool s_json_get_srv_uid(dap_json_t *a_json, const char *a_key_service_id, const char *a_key_service, uint64_t *a_out)
{
    uint64_t l_srv_id;
    if(!a_out)
        return false;
    // Read service id
    const char *l_id = s_json_get_text(a_json, a_key_service_id);
    
    if(l_id && sscanf(l_id,"0x%016"DAP_UINT64_FORMAT_x, &l_srv_id) == 1) {
        *a_out = l_srv_id;
        return true;
    }
    else {
        // Read service as name
        const char *l_service = s_json_get_text(a_json, a_key_service);
        if (l_service)
            *a_out = dap_chain_srv_get_uid_by_name(l_service).uint64;
    }
    return false;
}

static dap_chain_wallet_t* s_json_get_wallet(dap_json_t *a_json, const char *a_key)
{
    return dap_chain_wallet_open(s_json_get_text(a_json, a_key), dap_chain_wallet_get_path(g_config), NULL);
}

static const dap_cert_t* s_json_get_cert(dap_json_t *a_json, const char *a_key)
{
    return dap_cert_find_by_name(s_json_get_text(a_json, a_key));
}

// Read pkey from wallet or cert
static dap_pkey_t* s_json_get_pkey(dap_json_t *a_json)
{
    dap_pkey_t *l_pub_key = NULL;
    // From wallet
    dap_chain_wallet_t *l_wallet = s_json_get_wallet(a_json, "wallet");
    if(l_wallet) {
        l_pub_key = dap_chain_wallet_get_pkey(l_wallet, 0);
        dap_chain_wallet_close(l_wallet);
        if(l_pub_key) {
            return l_pub_key;
        }
    }
    // From cert
    const dap_cert_t *l_cert = s_json_get_cert(a_json, "cert");
    if(l_cert) {
        l_pub_key = dap_pkey_from_enc_key(l_cert->enc_key);
    }
    return l_pub_key;
}


static int s_dap_chain_net_tx_json_check(size_t a_items_count, dap_json_t *a_json_item_objs, dap_json_t *a_jobj_arr_errors, dap_chain_net_t * a_net) {
    // First iteration in input file. Check the tx will be multichannel or not
    int check = 0;
    int res = DAP_CHAIN_NET_TX_NORMAL;
    for(size_t i = 0; i < a_items_count; ++i) {
        dap_json_t *l_json_item_obj = dap_json_array_get_idx(a_json_item_objs, i);
        if(!l_json_item_obj || !dap_json_is_object(l_json_item_obj)) {
            continue;
        }
        const char *l_item_type_str = dap_json_object_get_string(l_json_item_obj, "type");
        if(!l_item_type_str) {
            log_it(L_WARNING, "Item %zu without type", i);
            continue;
        }
        dap_chain_tx_item_type_t l_item_type = dap_chain_datum_tx_item_type_from_str_short(l_item_type_str);
        if(l_item_type == TX_ITEM_TYPE_UNKNOWN) {
            log_it(L_WARNING, "Item %zu has invalid type '%s'", i, l_item_type_str);
            continue;
        }

        switch (l_item_type) {
            case TX_ITEM_TYPE_IN: {
                const char *l_prev_hash_str = s_json_get_text(l_json_item_obj, "prev_hash");
                uint64_t l_out_prev_idx;
                bool l_is_out_prev_idx = s_json_get_int64_uint64(l_json_item_obj, "out_prev_idx", &l_out_prev_idx, true);
                // If prev_hash and out_prev_idx were read
                if(l_prev_hash_str && l_is_out_prev_idx){
                    dap_chain_hash_fast_t l_tx_prev_hash = {};
                    if(!dap_chain_hash_fast_from_str(l_prev_hash_str, &l_tx_prev_hash)) {
                        //check out token
                        dap_chain_datum_tx_t *l_prev_tx = dap_ledger_tx_find_by_hash(a_net->pub.ledger, &l_tx_prev_hash);
                        byte_t *l_prev_item = l_prev_tx ? dap_chain_datum_tx_item_get_nth(l_prev_tx, TX_ITEM_TYPE_OUT_ALL, l_out_prev_idx) : NULL;
                        if (l_prev_item){
                            const char* l_token = NULL;
                            if (*l_prev_item == TX_ITEM_TYPE_OUT){
                                l_token = dap_ledger_tx_get_token_ticker_by_hash(a_net->pub.ledger, &l_tx_prev_hash);
                            } else if(*l_prev_item == TX_ITEM_TYPE_OUT_EXT){
                                l_token = ((dap_chain_tx_out_ext_t*)l_prev_item)->token;
                            } else if (*l_prev_item == TX_ITEM_TYPE_OUT_STD) {
                                l_token = ((dap_chain_tx_out_std_t *)l_prev_item)->token;
                            } else {
                                log_it(L_WARNING, "Invalid 'in' item, wrong type of item with index %"DAP_UINT64_FORMAT_U" in previous tx %s", l_out_prev_idx, l_prev_hash_str);
                                if (a_jobj_arr_errors)
                                    dap_json_rpc_error_add(a_jobj_arr_errors,-1,"Unable to create in for transaction. Invalid 'in' item, "
                                                                    "wrong type of item with index %"DAP_UINT64_FORMAT_U" in previous tx %s", l_out_prev_idx, l_prev_hash_str);
                                break;
                            }
                            UNUSED(l_token);
                        } else {
                            log_it(L_WARNING, "Invalid 'in' item, can't find item with index %"DAP_UINT64_FORMAT_U" in previous tx %s", l_out_prev_idx, l_prev_hash_str);
                            if (a_jobj_arr_errors)
                                dap_json_rpc_error_add(a_jobj_arr_errors,-1,"Unable to create in for transaction. Invalid 'in' item, "
                                                                "can't find item with index %"DAP_UINT64_FORMAT_U" in previous tx %s", l_out_prev_idx, l_prev_hash_str);
                        }                            
                    } else {
                        log_it(L_WARNING, "Invalid 'in' item, bad prev_hash %s", l_prev_hash_str);
                        if (a_jobj_arr_errors)
                            dap_json_rpc_error_add(a_jobj_arr_errors,-1,"Unable to create in for transaction. Invalid 'in' item, "
                                                            "bad prev_hash %s", l_prev_hash_str);
                    }
                }
            }break;
            case TX_ITEM_TYPE_IN_COND: {
                const char *l_prev_hash_str = s_json_get_text(l_json_item_obj, "prev_hash");
                uint64_t l_out_prev_idx;
                char l_delegated_ticker_str[DAP_CHAIN_TICKER_SIZE_MAX] 	=	{};
                bool l_is_out_prev_idx = s_json_get_int64_uint64(l_json_item_obj, "out_prev_idx", &l_out_prev_idx, true);
                if(l_prev_hash_str && l_is_out_prev_idx){
                    dap_chain_hash_fast_t l_tx_prev_hash = {};
                    dap_chain_tx_out_cond_t	*l_tx_out_cond = NULL;
                    dap_chain_datum_token_t *l_delegated_token;
                    if(!dap_chain_hash_fast_from_str(l_prev_hash_str, &l_tx_prev_hash)) {
                        dap_chain_datum_tx_t *l_prev_tx = dap_ledger_tx_find_by_hash(a_net->pub.ledger, &l_tx_prev_hash);
                        byte_t *l_item; size_t l_tx_item_size;
                        if (l_prev_tx)
                            TX_ITEM_ITER_TX(l_item, l_tx_item_size, l_prev_tx) {
                                if (*l_item == TX_ITEM_TYPE_OUT_COND) {
                                    l_tx_out_cond = (dap_chain_tx_out_cond_t*)l_item;                                
                                    if (l_tx_out_cond && l_tx_out_cond->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK) {
                                        const char *l_ticker_str = dap_ledger_tx_get_token_ticker_by_hash(a_net->pub.ledger, &l_tx_prev_hash);
                                        dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker_str, l_ticker_str);
                                        if (NULL != (l_delegated_token = dap_ledger_token_ticker_check(a_net->pub.ledger, l_delegated_ticker_str))){                                            
                                            check++;
                                            res = DAP_CHAIN_NET_TX_STAKE_UNLOCK;
                                        }                                    
                                    }
                                    /*
                                    if (l_tx_out_cond->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE) {
                                        SUM_256_256(l_value_order_back, l_tx_out_cond->header.value, &l_value_order_back);
                                    }*/
                                }
                            }
                    }
                }
            }break;
            case TX_ITEM_TYPE_IN_EMS: {
                const char *l_emission_hash_str = s_json_get_text(l_json_item_obj, "emission_hash");
                const char *l_json_item_token = s_json_get_text(l_json_item_obj, "token");
                if (l_json_item_token){
                    if (dap_strcmp(l_json_item_token, a_net->pub.native_ticker))//not native
                    {
                        if (!l_emission_hash_str){ //stake
                            check++;
                            res = DAP_CHAIN_NET_TX_STAKE_LOCK;
                        }                                 
                    }
                }
            }break;            
            case TX_ITEM_TYPE_IN_REWARD:{
                uint256_t l_value = { };
                bool l_is_value = s_json_get_uint256(l_json_item_obj, "value", &l_value);
                if (l_is_value) {
                    check++;
                    res = DAP_CHAIN_NET_TX_REWARD;
                }                
                break;
            }
            default: continue;
        }
        //if(l_multichanel)
            //break;
    }

    if (check > 1) {
        if (a_jobj_arr_errors)
            dap_json_rpc_error_add(a_jobj_arr_errors,-1,"Recognized more than one transaction type");
        res = DAP_CHAIN_NET_TX_TYPE_ERR;
    }
    return res;

}

static uint8_t *s_dap_chain_net_tx_create_in_item (dap_json_t *a_json_item_obj, dap_json_t *a_jobj_arr_errors) {
    // Save item obj for in
    // Read prev_hash and out_prev_idx
    const char *l_prev_hash_str = s_json_get_text(a_json_item_obj, "prev_hash");
    uint64_t l_out_prev_idx;
    bool l_is_out_prev_idx = s_json_get_int64_uint64(a_json_item_obj, "out_prev_idx", &l_out_prev_idx, true);
    // If prev_hash and out_prev_idx were read
    if(l_prev_hash_str && l_is_out_prev_idx) {
        dap_chain_hash_fast_t l_tx_prev_hash;
        if(!dap_chain_hash_fast_from_str(l_prev_hash_str, &l_tx_prev_hash)) {
            // Create IN item
            dap_chain_tx_in_t *l_in_item = dap_chain_datum_tx_item_in_create(&l_tx_prev_hash, (uint32_t) l_out_prev_idx);
            if (!l_in_item) {
                if (a_jobj_arr_errors)
                    dap_json_rpc_error_add(a_jobj_arr_errors, -1, "Unable to create in for transaction."); 
                return NULL;               
            }
            return (uint8_t *)l_in_item;
        } else {
            log_it(L_WARNING, "Invalid 'in' item, bad prev_hash %s", l_prev_hash_str);
            if (a_jobj_arr_errors)
                dap_json_rpc_error_add(a_jobj_arr_errors, -1, "Unable to create in for transaction. Invalid 'in' item, "
                                                "bad prev_hash %s", l_prev_hash_str);
        }
    }    
    return NULL;
}

static uint8_t *s_dap_chain_net_tx_create_in_ems_item (dap_json_t *a_json_item_obj, dap_json_t *a_jobj_arr_errors) {
    dap_chain_id_t l_chain_id;
    uint64_t l_chain_id_int;
    bool l_is_chain_id = s_json_get_int64_uint64(a_json_item_obj, "chain_id", &l_chain_id_int, true);
    l_chain_id.uint64 = l_chain_id_int;
    const char *l_json_item_token = s_json_get_text(a_json_item_obj, "token");
    if (l_json_item_token && l_is_chain_id){
        dap_hash_fast_t l_token_ems_hash = {};
        const char *l_json_item_token_ems_hash = s_json_get_text(a_json_item_obj, "token_ems_hash");
        if (l_json_item_token_ems_hash && dap_chain_hash_fast_from_str(l_json_item_token_ems_hash, &l_token_ems_hash)) {
            log_it(L_WARNING, "Invalid 'in_ems' item, bad hash");
            dap_json_rpc_error_add(a_jobj_arr_errors, -1, "Unable to create in for transaction. Invalid 'in_ems' item, bad hash");
            return NULL;
        }
        dap_chain_tx_in_ems_t *l_in_ems = dap_chain_datum_tx_item_in_ems_create(l_chain_id, &l_token_ems_hash, l_json_item_token);
        return (uint8_t *)l_in_ems;

    } else {
        char *l_str_err = NULL;
        if (!l_is_chain_id) {
            log_it(L_WARNING, "Invalid 'in_ems' item, can't read chain_id");
            if (a_jobj_arr_errors)
                dap_json_rpc_error_add(a_jobj_arr_errors, -1, "Unable to create in for transaction. Invalid 'in_ems' item, can't read chain_id");
        }
        if (!l_json_item_token){
            log_it(L_WARNING, "Invalid 'in_ems' item, bad token");
            if (a_jobj_arr_errors)
                dap_json_rpc_error_add(a_jobj_arr_errors, -1, "Unable to create in for transaction. Invalid 'in_ems' item, bad token");
        }
    }
    return NULL;
}

static uint8_t *s_dap_chain_net_tx_create_in_reward_item (dap_json_t *a_json_item_obj, dap_json_t *a_jobj_arr_errors) {
    uint256_t l_value = { };
    const char *l_block_hash_str = s_json_get_text(a_json_item_obj, "block_hash");
    bool l_is_value = s_json_get_uint256(a_json_item_obj, "value", &l_value);
    if(l_block_hash_str ) {
        dap_hash_fast_t l_block_hash;
        if(l_is_value && !dap_chain_hash_fast_from_str(l_block_hash_str, &l_block_hash)) {                             
            dap_chain_tx_in_reward_t *l_in_reward = dap_chain_datum_tx_item_in_reward_create(&l_block_hash);
            return (uint8_t *)l_in_reward;
        } else {
            log_it(L_WARNING, "Invalid 'in_reward' item, bad block_hash %s", l_block_hash_str);
            if (a_jobj_arr_errors)
                dap_json_rpc_error_add(a_jobj_arr_errors, -1, "Invalid 'in_reward' item, bad block_hash %s", l_block_hash_str);
        }
    }
    return NULL;
}

static uint8_t *s_dap_chain_net_tx_create_in_cond_item (dap_json_t *a_json_item_obj, dap_json_t *a_jobj_arr_errors, dap_chain_net_t *a_net) {
    const char *l_prev_hash_str = s_json_get_text(a_json_item_obj, "prev_hash");
    uint64_t l_out_prev_idx;
    bool l_is_out_prev_idx = s_json_get_int64_uint64(a_json_item_obj, "out_prev_idx", &l_out_prev_idx, true);
    if(l_prev_hash_str && l_is_out_prev_idx){
        dap_chain_hash_fast_t l_tx_prev_hash = {};
        dap_chain_tx_out_cond_t	*l_tx_out_cond = NULL;
        if(!dap_chain_hash_fast_from_str(l_prev_hash_str, &l_tx_prev_hash)) {
            if (!a_net) {
                uint64_t l_receipt_idx = 0;
                s_json_get_int64_uint64(a_json_item_obj, "receipt_idx", &l_receipt_idx, true);
                return (uint8_t *)dap_chain_datum_tx_item_in_cond_create(&l_tx_prev_hash, l_out_prev_idx, l_receipt_idx);
            }
            //check out token
            dap_chain_datum_tx_t *l_prev_tx = dap_ledger_tx_find_by_hash(a_net->pub.ledger, &l_tx_prev_hash);
            byte_t *l_item; size_t l_tx_item_size;
            if (l_prev_tx)
                TX_ITEM_ITER_TX(l_item, l_tx_item_size, l_prev_tx) {
                    if (*l_item == TX_ITEM_TYPE_OUT_COND) {
                        l_tx_out_cond = (dap_chain_tx_out_cond_t*)l_item;
                        if (l_tx_out_cond && l_tx_out_cond->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK) {
                            byte_t *l_prev_item = l_prev_tx ? dap_chain_datum_tx_item_get_nth(l_prev_tx, TX_ITEM_TYPE_OUT_ALL, l_out_prev_idx) : NULL;                          
                            if (l_prev_item){
                                if (*l_prev_item == TX_ITEM_TYPE_OUT_COND){
                                    dap_chain_tx_in_cond_t * l_in_cond = dap_chain_datum_tx_item_in_cond_create(&l_tx_prev_hash, l_out_prev_idx, 0);
                                    return (uint8_t *)l_in_cond;                           
                                } else {
                                    log_it(L_WARNING, "Invalid 'in_cond' item, wrong type of item with index %"DAP_UINT64_FORMAT_U" in previous tx %s", l_out_prev_idx, l_prev_hash_str);
                                    if (a_jobj_arr_errors)
                                        dap_json_rpc_error_add(a_jobj_arr_errors, -1, "Unable to create in for transaction. Invalid 'in_cond' item, "
                                                                        "wrong type of item with index %"DAP_UINT64_FORMAT_U" in previous tx %s", l_out_prev_idx, l_prev_hash_str);
                                    return NULL;
                                }                                                         
                            } else {
                                log_it(L_WARNING, "Invalid 'in_cond' item, can't find item with index %"DAP_UINT64_FORMAT_U" in previous tx %s", l_out_prev_idx, l_prev_hash_str);
                                dap_json_rpc_error_add(a_jobj_arr_errors, -1, "Unable to create in for transaction. Invalid 'in_cond' item, "
                                                                    "can't find item with index %"DAP_UINT64_FORMAT_U" in previous tx %s", l_out_prev_idx, l_prev_hash_str);
                            }               
                        }
                        if (l_tx_out_cond && l_tx_out_cond->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE) {
                            dap_chain_tx_in_cond_t * l_in_cond = dap_chain_datum_tx_item_in_cond_create(&l_tx_prev_hash, l_out_prev_idx, 0);
                            return (uint8_t *)l_in_cond;
                        }  
                    }
                }                 
        } else {
            log_it(L_WARNING, "Invalid 'in_cond' item, bad prev_hash %s", l_prev_hash_str);
            dap_json_rpc_error_add(a_jobj_arr_errors, -1, "Unable to create in for transaction. Invalid 'in_cond' item, "
                                                "bad prev_hash %s", l_prev_hash_str);
        }
    }
    return NULL; 
}    

static uint8_t *s_dap_chain_net_tx_create_out_ext_item (dap_json_t *a_json_item_obj, dap_json_t *a_jobj_errors, int a_type_tx) {
    // Read address and value
    uint256_t l_value = { };
    const char *l_json_item_addr_str = s_json_get_text(a_json_item_obj, "addr");
    bool l_is_value = s_json_get_uint256(a_json_item_obj, "value", &l_value);
    const char *l_token = s_json_get_text(a_json_item_obj, "token");
    if (l_is_value && l_json_item_addr_str) {
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
        dap_chain_addr_t *l_addr = dap_chain_addr_from_str(l_json_item_addr_str);
#else
        size_t l_addr_size = DAP_ENC_BASE58_DECODE_SIZE(strlen(l_json_item_addr_str));
        dap_chain_addr_t *l_addr = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_addr_t, dap_max(sizeof(dap_chain_addr_t), l_addr_size), NULL);
        if (l_json_item_addr_str) {
            if (strcmp("null", l_json_item_addr_str)) {
                if (dap_enc_base58_decode(l_json_item_addr_str, l_addr) != sizeof(dap_chain_addr_t)) {
                    DAP_DELETE(l_addr);
                    return NULL;
                }
            }
        }
#endif
        if((!dap_strcmp(l_json_item_addr_str,"null") || l_addr) && !IS_ZERO_256(l_value)) {            
            // Create OUT item
            uint8_t *l_out_item = NULL;
            
            if (a_type_tx == DAP_CHAIN_NET_TX_STAKE_UNLOCK && l_is_value && !dap_strcmp(l_json_item_addr_str,"null")) {
                l_out_item = (uint8_t *)dap_chain_datum_tx_item_out_ext_create(&c_dap_chain_addr_blank_1, l_value, l_token);            
            } else {
                l_out_item = (uint8_t *)dap_chain_datum_tx_item_out_ext_create(l_addr, l_value, l_token);
            }
            if (l_addr) DAP_DELETE(l_addr);
            return l_out_item;      
        }
        if (l_addr) DAP_DELETE(l_addr);
    }
    return NULL;
}


static uint8_t *s_dap_chain_net_tx_create_out_std_item (dap_json_t *a_json_item_obj, dap_json_t *a_jobj_errors, int a_type_tx) {
    // Read address and value
    uint256_t l_value = { };
    const char *l_json_item_addr_str = s_json_get_text(a_json_item_obj, "addr");
    bool l_is_value = s_json_get_uint256(a_json_item_obj, "value", &l_value);
    const char *l_token = s_json_get_text(a_json_item_obj, "token");
    dap_time_t l_time_unlock = 0;
    const char* l_time_unlock_str = s_json_get_text(a_json_item_obj, "time_unlock");
    if (l_time_unlock_str && sscanf(l_time_unlock_str, "%"DAP_UINT64_FORMAT_U, &l_time_unlock) != 1){
        log_it(L_ERROR, "Json TX: bad time_unlock");
        return NULL;
    }
    if (l_is_value && (l_json_item_addr_str)) {
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
        dap_chain_addr_t *l_addr = dap_chain_addr_from_str(l_json_item_addr_str);
#else
        size_t l_addr_size = DAP_ENC_BASE58_DECODE_SIZE(strlen(l_json_item_addr_str));
        dap_chain_addr_t *l_addr = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_addr_t, dap_max(sizeof(dap_chain_addr_t), l_addr_size), NULL);
        if (l_json_item_addr_str) {
            if (strcmp("null", l_json_item_addr_str)) {
                if (dap_enc_base58_decode(l_json_item_addr_str, l_addr) != sizeof(dap_chain_addr_t)) {
                    DAP_DELETE(l_addr);
                    return NULL;
                }
            }
        }
#endif
        if((!dap_strcmp(l_json_item_addr_str,"null") || l_addr) && !IS_ZERO_256(l_value)) {            
            // Create OUT item
            uint8_t *l_out_item = NULL;
            
            if (a_type_tx == DAP_CHAIN_NET_TX_STAKE_UNLOCK && l_is_value && !dap_strcmp(l_json_item_addr_str,"null")) {
                l_out_item = (uint8_t *)dap_chain_datum_tx_item_out_std_create(&c_dap_chain_addr_blank_1, l_value, l_token, l_time_unlock);            
            } else {
                l_out_item = (uint8_t *)dap_chain_datum_tx_item_out_std_create(l_addr, l_value, l_token, l_time_unlock);
            }
            if (l_addr) DAP_DELETE(l_addr);
            return l_out_item;      
        }
        if (l_addr) DAP_DELETE(l_addr);
    }
    return NULL;
}

static uint8_t *s_dap_chain_net_tx_create_out_cond_item (dap_json_t *a_json_item_obj, dap_json_t *a_jobj_arr_errors, int a_type_tx,
                uint256_t *a_value_need, dap_chain_addr_t *a_seller_addr, size_t i, dap_chain_net_t *a_net)
{
    // Read subtype of item
    const char *l_subtype_str = s_json_get_text(a_json_item_obj, "subtype");
    dap_chain_tx_out_cond_subtype_t l_subtype = dap_chain_tx_out_cond_subtype_from_str_short(l_subtype_str);
    switch (l_subtype) {
        case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY:{
            uint256_t l_value = { };
            bool l_is_value = s_json_get_uint256(a_json_item_obj, "value", &l_value);
            if(!l_is_value || IS_ZERO_256(l_value)) {
                dap_json_rpc_error_add(a_jobj_arr_errors, -1, "Json TX: bad value in OUT_COND_SUBTYPE_SRV_PAY");
                log_it(L_ERROR, "Json TX: bad value in OUT_COND_SUBTYPE_SRV_PAY");
                return NULL;
            }
            uint256_t l_value_max_per_unit = { };
            l_is_value = s_json_get_uint256(a_json_item_obj, "value_max_per_unit", &l_value_max_per_unit);
            // always value_max_per_unit ==  0
            // if(!l_is_value) {
            //     log_it(L_ERROR, "Json TX: bad value_max_per_unit in OUT_COND_SUBTYPE_SRV_PAY");
            //     return NULL;
            // }
            dap_chain_net_srv_price_unit_uid_t l_price_unit;
            if(!s_json_get_unit(a_json_item_obj, "price_unit", &l_price_unit)) {
                log_it(L_ERROR, "Json TX: bad price_unit in OUT_COND_SUBTYPE_SRV_PAY");
                return NULL;
            }
            uint64_t l_srv_uid = 0;
            if(!s_json_get_srv_uid(a_json_item_obj, "service_id", "service", &l_srv_uid)){
                // Default service DAP_CHAIN_NET_SRV_VPN_ID
                l_srv_uid = 0x0000000000000001;
            }
            const char *l_params_str = s_json_get_text(a_json_item_obj, "params");
            uint8_t *l_params = NULL;
            size_t l_params_size = 0;
            if (l_params_str) {
                l_params_size = DAP_ENC_BASE58_DECODE_SIZE(dap_strlen(l_params_str));
                l_params = DAP_NEW_Z_SIZE(uint8_t, l_params_size);
                l_params_size = dap_enc_base58_decode(l_params_str, l_params);
            }

            const char *l_pkey_hash_str = s_json_get_text(a_json_item_obj, "pkey_hash");
            dap_chain_tx_out_cond_t *l_out_cond_item = NULL;
            dap_hash_fast_t l_pkey_hash = {};
            // From "wallet" or "cert"
            dap_pkey_t *l_pkey = s_json_get_pkey(a_json_item_obj);
            if(l_pkey) {
                l_out_cond_item = dap_chain_datum_tx_item_out_cond_create_srv_pay(l_pkey, (dap_chain_srv_uid_t){.uint64 = l_srv_uid}, l_value, l_value_max_per_unit,
                    l_price_unit, l_params, l_params_size);
                DAP_DELETE(l_pkey);
            } else if (l_pkey_hash_str && !dap_chain_hash_fast_from_str(l_pkey_hash_str, &l_pkey_hash)) {
                l_out_cond_item = dap_chain_datum_tx_item_out_cond_create_srv_pay_with_hash(&l_pkey_hash, (dap_chain_srv_uid_t){.uint64 = l_srv_uid}, l_value, l_value_max_per_unit,
                    l_price_unit, l_params, l_params_size);
            } else {
                dap_json_rpc_error_add(a_jobj_arr_errors, -1, "Json TX: bad pkey in OUT_COND_SUBTYPE_SRV_PAY");
                log_it(L_ERROR, "Json TX: bad pkey in OUT_COND_SUBTYPE_SRV_PAY");
                DAP_DELETE(l_params);
                return NULL;
            }
            DAP_DELETE(l_params);
            // Save value for using in In item
            if(!l_out_cond_item) {
                if (a_jobj_arr_errors)
                    dap_json_rpc_error_add(a_jobj_arr_errors, -1, "Unable to create conditional out for transaction "
                                                    "can of type %s described in item %zu.\n", l_subtype_str, i);
            } else
                return (uint8_t *)l_out_cond_item;


        } break;
        case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE: {

            uint64_t l_srv_uid = 0;
            if(!s_json_get_srv_uid(a_json_item_obj, "service_id", "service", &l_srv_uid)) {
                // Default service DAP_CHAIN_NET_SRV_XCHANGE_ID
                l_srv_uid = 0x2;
            }
            dap_chain_net_id_t l_buy_net_id = {}; 
            if(dap_chain_net_id_parse(s_json_get_text(a_json_item_obj, "buy_net_id"), &l_buy_net_id)) {
                dap_json_rpc_error_add(a_jobj_arr_errors, -1, "Json TX: buy_net_id net in OUT_COND_SUBTYPE_SRV_XCHANGE");
                log_it(L_ERROR, "Json TX: buy_net_id net in OUT_COND_SUBTYPE_SRV_XCHANGE");
                return NULL;
            }  
            dap_chain_net_id_t l_sell_net_id = {}; 
            if(dap_chain_net_id_parse(s_json_get_text(a_json_item_obj, "sell_net_id"), &l_sell_net_id)) {
                dap_json_rpc_error_add(a_jobj_arr_errors, -1, "Json TX: sell_net_id net in OUT_COND_SUBTYPE_SRV_XCHANGE");
                log_it(L_ERROR, "Json TX: sell_net_id net in OUT_COND_SUBTYPE_SRV_XCHANGE");
                return NULL;
            }              

            const char *l_token_buy = s_json_get_text(a_json_item_obj, "buy_token");
            if(!l_token_buy) {
                dap_json_rpc_error_add(a_jobj_arr_errors, -1, "Json TX: bad buy_token in OUT_COND_SUBTYPE_SRV_XCHANGE");
                log_it(L_ERROR, "Json TX: bad buy_token in OUT_COND_SUBTYPE_SRV_XCHANGE");
                return NULL;
            }
            uint256_t l_value = { };
            if(!s_json_get_uint256(a_json_item_obj, "value", &l_value) || IS_ZERO_256(l_value)) {
                dap_json_rpc_error_add(a_jobj_arr_errors, -1, "Json TX: bad value in OUT_COND_SUBTYPE_SRV_XCHANGE");
                log_it(L_ERROR, "Json TX: bad value in OUT_COND_SUBTYPE_SRV_XCHANGE");
                return NULL;
            }
            uint256_t l_value_rate = { };
            if(!s_json_get_uint256(a_json_item_obj, "rate", &l_value_rate) || IS_ZERO_256(l_value_rate)) {
                dap_json_rpc_error_add(a_jobj_arr_errors, -1, "Json TX: bad value rate in OUT_COND_SUBTYPE_SRV_XCHANGE");
                log_it(L_ERROR, "Json TX: bad value rate in OUT_COND_SUBTYPE_SRV_XCHANGE");
                return NULL;
            }
            const char *l_seller_addr_str = s_json_get_text(a_json_item_obj, "seller_addr");
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
                dap_chain_addr_t *l_seller_addr = dap_chain_addr_from_str(l_seller_addr_str);
#else
                size_t l_addr_size = DAP_ENC_BASE58_DECODE_SIZE(strlen(l_seller_addr_str));
                dap_chain_addr_t *l_seller_addr = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_addr_t, l_addr_size, NULL);
                if (dap_enc_base58_decode(l_seller_addr_str, l_seller_addr) != sizeof(dap_chain_addr_t)) {
                    DAP_DELETE(l_seller_addr);
                    return NULL;
                }
#endif

            const char *l_params_str = s_json_get_text(a_json_item_obj, "params");
            uint8_t *l_params = NULL;
            size_t l_params_size = 0;
            if (l_params_str) {
                l_params_size = DAP_ENC_BASE58_DECODE_SIZE(dap_strlen(l_params_str));
                l_params = DAP_NEW_Z_SIZE(uint8_t, l_params_size);
                l_params_size = dap_enc_base58_decode(l_params_str, l_params);
            }

            dap_chain_tx_out_cond_t *l_out_cond_item = dap_chain_datum_tx_item_out_cond_create_srv_xchange((dap_chain_srv_uid_t){.uint64 = l_srv_uid},
                                                                                                            l_sell_net_id,
                                                                                                            l_value, l_buy_net_id,
                                                                                                            l_token_buy, l_value_rate,
                                                                                                            l_seller_addr,
                                                                                                            l_params, l_params_size);
            DAP_DELETE(l_params);
            DAP_DELETE(l_seller_addr);
            // Save value for using in In item
            if (l_out_cond_item) {
                return (uint8_t *)l_out_cond_item;
            } else {
                if (a_jobj_arr_errors)
                    dap_json_rpc_error_add(a_jobj_arr_errors, -1, "Unable to create conditional out for transaction "
                                                     "can of type %s described in item %zu.", l_subtype_str, i);
            }
        } break;
        case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK:{
            uint64_t l_srv_uid = 0;
            if(!s_json_get_srv_uid(a_json_item_obj, "service_id", "service", &l_srv_uid)) {
                // Default service DAP_CHAIN_NET_SRV_STAKE_ID
                l_srv_uid = 0x12;
            }
            uint256_t l_value = { };
            if(!s_json_get_uint256(a_json_item_obj, "value", &l_value) || IS_ZERO_256(l_value)) {
                dap_json_rpc_error_add(a_jobj_arr_errors, -1, "Json TX: bad value in DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK");
                log_it(L_ERROR, "Json TX: bad value in DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK");
                return NULL;
            }

            dap_time_t l_time_staking = 0;
            const char* l_time_staking_str = s_json_get_text(a_json_item_obj, "time_staking");
            if (sscanf(l_time_staking_str, "%"DAP_UINT64_FORMAT_U, &l_time_staking) != 1 || !l_time_staking){
                dap_json_rpc_error_add(a_jobj_arr_errors, -1, "Json TX: bad time staking in DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK");
                log_it(L_ERROR, "Json TX: bad time staking in DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK");
                return NULL;
            }
            // if (l_time_staking < dap_time_now()){
            //     log_it(L_ERROR, "Json TX: past time staking in DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK");
            //     return NULL;
            // }

            uint256_t l_reinvest_percent = uint256_0;
            const char* l_reinvest_percent_str = NULL;
            if((l_reinvest_percent_str = s_json_get_text(a_json_item_obj, "reinvest_percent"))!=NULL) {
                l_reinvest_percent = dap_chain_balance_coins_scan(l_reinvest_percent_str);
                if (compare256(l_reinvest_percent, dap_chain_balance_coins_scan("100.0")) == 1) {
                    dap_json_rpc_error_add(a_jobj_arr_errors, -1, "Json TX: bad reinvest percent in DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK");
                    log_it(L_ERROR, "Json TX: bad reinvest percent in DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK");
                    return NULL;
                }
                if (IS_ZERO_256(l_reinvest_percent)) {
                    int l_reinvest_percent_int = atoi(l_reinvest_percent_str);
                    if (l_reinvest_percent_int < 0 || l_reinvest_percent_int > 100){
                        dap_json_rpc_error_add(a_jobj_arr_errors, -1, "Json TX: bad reinvest percent in DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK");
                        log_it(L_ERROR, "Json TX: bad reinvest percent in DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK");
                        return NULL;
                    }
                    l_reinvest_percent = dap_chain_uint256_from(l_reinvest_percent_int);
                    MULT_256_256(l_reinvest_percent, GET_256_FROM_64(1000000000000000000ULL), &l_reinvest_percent);
                }
            }               

            dap_chain_tx_out_cond_t *l_out_cond_item = dap_chain_datum_tx_item_out_cond_create_srv_stake_lock((dap_chain_srv_uid_t){.uint64 = l_srv_uid}, l_value, l_time_staking, l_reinvest_percent);
            if (l_out_cond_item) {
                uint64_t l_flags = 0;
                if (s_json_get_int64_uint64(a_json_item_obj, "flags", &l_flags, true)) {
                    l_out_cond_item->subtype.srv_stake_lock.flags = l_flags;
                }

            // Save value for using in In item
                return (uint8_t *)l_out_cond_item;
            } else {
                if (a_jobj_arr_errors)
                    dap_json_rpc_error_add(a_jobj_arr_errors, -1, "Unable to create conditional out for transaction "
                                                     "can of type %s described in item %zu.", l_subtype_str, i);
            }
        } break;
        case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE:{
            uint64_t l_srv_uid = 0;
            if(!s_json_get_srv_uid(a_json_item_obj, "service_id", "service", &l_srv_uid)) {
                // Default service DAP_CHAIN_NET_SRV_STAKE_ID
                l_srv_uid = 0x13;
            }
            uint256_t l_value = { };
            if(!s_json_get_uint256(a_json_item_obj, "value", &l_value) || IS_ZERO_256(l_value)) {
                dap_json_rpc_error_add(a_jobj_arr_errors, -1, "Json TX: bad value in OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE");
                log_it(L_ERROR, "Json TX: bad value in OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE");
                return NULL;
            }
            // uint256_t l_fee_value = { };
            // if(!s_json_get_uint256(a_json_item_obj, "fee", &l_fee_value) || IS_ZERO_256(l_fee_value)) {
            //     return NULL;
            // }

            const char *l_signing_addr_str = s_json_get_text(a_json_item_obj, "signing_addr");
#ifndef DAP_CHAIN_TX_COMPOSE_TEST
            dap_chain_addr_t *l_signing_addr = dap_chain_addr_from_str(l_signing_addr_str);
#else
            size_t l_addr_size = DAP_ENC_BASE58_DECODE_SIZE(strlen(l_signing_addr_str));
            dap_chain_addr_t *l_signing_addr = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_addr_t, l_addr_size, NULL);
            if (dap_enc_base58_decode(l_signing_addr_str, l_signing_addr) != sizeof(dap_chain_addr_t)) {
                DAP_DELETE(l_signing_addr);
                return NULL;
            }
#endif
            if(!l_signing_addr) {
                dap_json_rpc_error_add(a_jobj_arr_errors, -1, "Json TX: bad signing_addr in OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE");
                log_it(L_ERROR, "Json TX: bad signing_addr in OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE");
                return NULL;
            }

            dap_chain_node_addr_t l_signer_node_addr;
            const char *l_node_addr_str = s_json_get_text(a_json_item_obj, "signer_node_addr");
            if(!l_node_addr_str || dap_chain_node_addr_from_str(&l_signer_node_addr, l_node_addr_str)) {
                dap_json_rpc_error_add(a_jobj_arr_errors, -1, "Json TX: bad node_addr in OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE");
                log_it(L_ERROR, "Json TX: bad node_addr in OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE");
                DAP_DELETE(l_signing_addr);
                return NULL;
            }

            const char *l_params_str = s_json_get_text(a_json_item_obj, "params");
            uint8_t *l_params = NULL;
            size_t l_params_size = 0;
            if (l_params_str) {
                l_params_size = DAP_ENC_BASE58_DECODE_SIZE(dap_strlen(l_params_str));
                l_params = DAP_NEW_Z_SIZE(uint8_t, l_params_size);
                l_params_size = dap_enc_base58_decode(l_params_str, l_params);
            }
            dap_chain_tx_out_cond_t *l_out_cond_item = dap_chain_datum_tx_item_out_cond_create_srv_stake_params((dap_chain_srv_uid_t){.uint64 = l_srv_uid},
                                                                                                                l_value, l_signing_addr,
                                                                                                         &l_signer_node_addr, uint256_0, l_params, l_params_size);
            DAP_DELETE(l_signing_addr);
            DAP_DELETE(l_params);
            // Save value for using in In item
            if(l_out_cond_item) {
                SUM_256_256(*a_value_need, l_value, a_value_need);
                uint64_t l_flags = 0;
                if (s_json_get_int64_uint64(a_json_item_obj, "flags", &l_flags, true)) {
                    l_out_cond_item->subtype.srv_stake_pos_delegate.flags = l_flags;
                }
                return (uint8_t *)l_out_cond_item;
            } else {
                if (a_jobj_arr_errors)
                    dap_json_rpc_error_add(a_jobj_arr_errors, -1, "Unable to create conditional out for transaction "
                                                    "can of type %s described in item %zu.", l_subtype_str, i);
            }
        } break;
        case DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE: {
            uint256_t l_value = { };
            s_json_get_uint256(a_json_item_obj, "value", &l_value);
            if(!IS_ZERO_256(l_value)) {
                if (a_type_tx == DAP_CHAIN_NET_TX_STAKE_UNLOCK){
                    dap_chain_tx_out_cond_t *l_out_cond_item = dap_chain_datum_tx_item_out_cond_create_fee(l_value);
                    return (uint8_t *)l_out_cond_item;
                }
                dap_chain_tx_out_cond_t *l_out_cond_item = dap_chain_datum_tx_item_out_cond_create_fee(l_value);
                // Save value for using in In item
                if(l_out_cond_item) {
                    return (uint8_t *)l_out_cond_item;
                } else {
                    if (a_jobj_arr_errors)
                        dap_json_rpc_error_add(a_jobj_arr_errors, -1, "Unable to create conditional out for transaction "
                                                        "can of type %s described in item %zu.", l_subtype_str, i);
                }
            }
            else
                log_it(L_ERROR, "Json TX: zero value in OUT_COND_SUBTYPE_FEE");
        } break;
        case DAP_CHAIN_TX_OUT_COND_SUBTYPE_UNDEFINED:{
            log_it(L_WARNING, "Undefined subtype: '%s' of 'out_cond' item %zu ", l_subtype_str, i);
            if (a_jobj_arr_errors)
                dap_json_rpc_error_add(a_jobj_arr_errors, -1, "Specified unknown sub type %s of conditional out on item %zu.",
                                                l_subtype_str, i); 
        }      
    }
    return NULL;
}

static uint8_t *s_dap_chain_net_tx_create_receipt_item(dap_json_t *a_json_item_obj, dap_json_t *a_jobj_arr_errors, dap_chain_datum_tx_t *a_tx, dap_list_t *a_sign_list, size_t i)
{
    uint64_t l_srv_uid = 0;
    if(!s_json_get_srv_uid(a_json_item_obj, "service_id", "service", &l_srv_uid)) {
        log_it(L_ERROR, "Json TX: bad service_id in TYPE_RECEIPT");
        return NULL;
    }
    dap_chain_net_srv_price_unit_uid_t l_price_unit;
    if(!s_json_get_unit(a_json_item_obj, "price_unit", &l_price_unit)) {
        log_it(L_ERROR, "Json TX: bad price_unit in TYPE_RECEIPT");
        return NULL;
    }
    uint64_t l_units;
    if(!s_json_get_int64_uint64(a_json_item_obj, "units", &l_units, true)) {
        log_it(L_ERROR, "Json TX: bad units in TYPE_RECEIPT");
        return NULL;
    }
    uint256_t l_value = { };
    if(!s_json_get_uint256(a_json_item_obj, "value", &l_value) || IS_ZERO_256(l_value)) {
        log_it(L_ERROR, "Json TX: bad value in TYPE_RECEIPT");
        return NULL;
    }
    const char *l_params_str = s_json_get_text(a_json_item_obj, "params");
    char *l_params = NULL;
    size_t l_params_size = 0;
    if (l_params_str) {
        l_params_size = DAP_ENC_BASE58_DECODE_SIZE(dap_strlen(l_params_str));
        l_params = DAP_NEW_Z_SIZE(char, l_params_size);
        l_params_size = dap_enc_base58_decode(l_params_str, l_params);
    }
    dap_hash_fast_t l_prev_tx_hash = {};
    const char* l_prev_tx_hash_str = NULL;
    if((l_prev_tx_hash_str = s_json_get_text(a_json_item_obj, "prev_tx")) == NULL) {
        log_it(L_ERROR, "Json TX: bad prev_tx in TYPE_RECEIPT");
        return NULL;
    }
    dap_chain_hash_fast_from_str(l_prev_tx_hash_str, &l_prev_tx_hash);
    dap_chain_datum_tx_receipt_t *l_receipt = dap_chain_datum_tx_receipt_create((dap_chain_srv_uid_t){.uint64 = l_srv_uid}, l_price_unit, l_units, l_value, l_params, l_params_size, &l_prev_tx_hash);
    if (!l_receipt) {
        if (a_jobj_arr_errors)
                dap_json_rpc_error_add(a_jobj_arr_errors, -1, "Unable to create receipt out for transaction "
                                            "described by item %zu.", i);        
        return NULL;
    } else
        return (uint8_t *)l_receipt;
}

static uint8_t *s_dap_chain_net_tx_create_tsd_item(dap_json_t *a_json_item_obj, dap_json_t *a_jobj_arr_errors, dap_chain_datum_tx_t *a_tx, dap_list_t *a_sign_list)
{
    int64_t l_tsd_type = 0;
    uint64_t l_tsd_data_size = 0;
        
    if(!s_json_get_int64_uint64(a_json_item_obj, "data_type", &l_tsd_type, false)) {
        log_it(L_ERROR, "Json TX: bad data_type in TYPE_TSD");
        return NULL;
    }
    if(!s_json_get_int64_uint64(a_json_item_obj, "data_size", &l_tsd_data_size, true) || !l_tsd_data_size) {
        log_it(L_ERROR, "Json TX: bad data_size in TYPE_TSD");
        return NULL;
    }
    const char *l_tsd_data_str = s_json_get_text(a_json_item_obj, "data");
    if (!l_tsd_data_str) {
        log_it(L_ERROR, "Json TX: bad data in TYPE_TSD");
        return NULL;
    }

    uint8_t *l_tsd_data = DAP_NEW_Z_SIZE(uint8_t, l_tsd_data_size);
    size_t l_tsd_data_size_decoded = dap_enc_base58_decode(l_tsd_data_str, l_tsd_data);
    if (l_tsd_data_size_decoded != l_tsd_data_size) {
        log_it(L_ERROR, "Json TX: data size in tsd section - %zu, expected - %zu", l_tsd_data_size_decoded, l_tsd_data_size);
        if (a_jobj_arr_errors)
                dap_json_rpc_error_add(a_jobj_arr_errors, -1, "Json TX: data size in tsd section - %zu, expected - %zu", l_tsd_data_size_decoded, l_tsd_data_size);
        DAP_DELETE(l_tsd_data);
        return NULL;
    }
    dap_chain_tx_tsd_t *l_tsd = dap_chain_datum_tx_item_tsd_create((void*)l_tsd_data, (int)l_tsd_type, l_tsd_data_size);
    DAP_DELETE(l_tsd_data);
    return (uint8_t *)l_tsd;
}

uint8_t *s_dap_chain_net_tx_create_sig_item(dap_json_t *a_json_item_obj, dap_json_t *a_jobj_arr_errors, dap_chain_datum_tx_t *a_tx, dap_list_t **a_sign_list)
{
    dap_json_t *l_jobj_sign = NULL;

    dap_json_object_get_ex(a_json_item_obj, "sig_b64", &l_jobj_sign);
    if (!l_jobj_sign) {
        *a_sign_list = dap_list_append(*a_sign_list, a_json_item_obj);
        return NULL;
    }
    const char *l_sign_b64_str = dap_json_get_string(l_jobj_sign);
    if ( !l_sign_b64_str ) {
        if (a_jobj_arr_errors)
                dap_json_rpc_error_add(a_jobj_arr_errors, -1, "Can't get base64-encoded sign");
        log_it(L_ERROR, "Json TX: Can't get base64-encoded sign!");
        return NULL;
    }
    uint64_t
        l_sign_size = 0,
        l_sign_b64_strlen = strlen(l_sign_b64_str),
        l_sign_decoded_size = DAP_ENC_BASE64_DECODE_SIZE(l_sign_b64_strlen);
    if ( !s_json_get_int64_uint64(a_json_item_obj, "sig_size", &l_sign_size, true) )
        log_it(L_NOTICE, "Json TX: \"sig_size\" unspecified, will be calculated automatically");

    uint64_t l_version = 1;
    s_json_get_int64_uint64(a_json_item_obj, "sig_version", &l_version, true); 
    
    dap_chain_tx_sig_t *l_tx_sig = DAP_NEW_Z_SIZE(dap_chain_tx_sig_t, sizeof(dap_chain_tx_sig_t) + l_sign_decoded_size);
    l_tx_sig->header.type = TX_ITEM_TYPE_SIG;
    l_tx_sig->header.version = l_version;
    l_tx_sig->header.sig_size = dap_enc_base64_decode(l_sign_b64_str, l_sign_b64_strlen, l_tx_sig->sig, DAP_ENC_DATA_TYPE_B64_URLSAFE);

    if ( l_tx_sig->header.sig_size  != l_sign_size || l_sign_size != dap_sign_get_size((dap_sign_t *)l_tx_sig->sig) ) {
        if (a_jobj_arr_errors)
                dap_json_rpc_error_add(a_jobj_arr_errors, -1, "Sign size failed!");
        log_it(L_ERROR, "Json TX: sign verification failed!");
        DAP_DELETE(l_tx_sig);
        return NULL;
    }
    return (uint8_t *)l_tx_sig;
}

uint8_t *s_dap_chain_net_tx_create_voting_item(dap_json_t *a_jobj_arr_errors)
{

    dap_chain_tx_voting_t* l_voting_item = dap_chain_datum_tx_item_voting_create();

    if (l_voting_item)
        return (uint8_t *)l_voting_item;
    else {
        if (a_jobj_arr_errors)
                dap_json_rpc_error_add(a_jobj_arr_errors, -1, "Can't create voiting item");
        log_it(L_ERROR, "Can't create voiting item");
        return NULL;
    }
}

uint8_t *s_dap_chain_net_tx_create_vote_item(dap_json_t *a_json_item_obj, dap_json_t *a_jobj_arr_errors)
{
    uint64_t l_value_idx;
    const char *l_voting_hash_str = s_json_get_text(a_json_item_obj, "voting_hash");
    bool l_is_value = s_json_get_int64_uint64(a_json_item_obj, "answer_idx", &l_value_idx, true);
    if(l_voting_hash_str ) {
        dap_hash_fast_t l_voting_hash;
        if(l_is_value && !dap_chain_hash_fast_from_str(l_voting_hash_str, &l_voting_hash)) {                             
            dap_chain_tx_vote_t *l_vote_item = dap_chain_datum_tx_item_vote_create(&l_voting_hash, &l_value_idx);
            return (uint8_t *)l_vote_item;
        } else {
            log_it(L_WARNING, "Invalid 'vote' item, bad voting_hash %s or answer_idx %"DAP_UINT64_FORMAT_U, l_voting_hash_str, l_value_idx);
            if (a_jobj_arr_errors)
                dap_json_rpc_error_add(a_jobj_arr_errors, -1, "Invalid 'vote' item, bad voting_hash %s", l_voting_hash_str);
        }
    }
    return NULL;
}

int s_find_add_token_val (const char *a_token, uint256_t a_value, int(*operation)(uint256_t, uint256_t, uint256_t *)){
    dap_tx_creator_tokenizer_t *l_value_cur = NULL;
    HASH_FIND_STR(s_values_need, a_token, l_value_cur);
    if (!l_value_cur) {
        l_value_cur = DAP_NEW_Z(dap_tx_creator_tokenizer_t);
        if ( !l_value_cur ) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            return DAP_CHAIN_NET_TX_CREATE_JSON_ENOUGH_MEMORY;
        }
        strcpy(l_value_cur->token_ticker, a_token);
        HASH_ADD_STR(s_values_need, token_ticker, l_value_cur);
    }
    if (operation(l_value_cur->sum, a_value, &l_value_cur->sum)) {
        return DAP_CHAIN_NET_TX_CREATE_JSON_INTEGER_OVERFLOW;
    }
    return 0;
}

static int s_free_token_hash (void) {
    dap_tx_creator_tokenizer_t *l_value_cur = NULL, *l_tmp = NULL;
    HASH_ITER(hh, s_values_need, l_value_cur, l_tmp) {
        HASH_DEL(s_values_need, l_value_cur);
        DAP_DELETE(l_value_cur);
    }
    return 0;
}

static int s_dap_chain_net_tx_add_in_and_back(dap_tx_creator_tokenizer_t *a_value_need, dap_json_t *a_jobj_errors, const dap_chain_addr_t * a_addr_from, dap_ledger_t *a_ledger, 
                                    dap_chain_datum_tx_t **a_tx, size_t *a_items_ready){
    // find the transactions from which to take away coins
    dap_list_t *l_list_used_out = NULL;
    uint256_t l_value_transfer = { }; // how many coins to transfer
    l_list_used_out = dap_chain_wallet_get_list_tx_outs_with_val(a_ledger, a_value_need->token_ticker,
                                                            a_addr_from, a_value_need->sum, &l_value_transfer);
    log_it(L_WARNING, "elements from list - %"DAP_UINT64_FORMAT_U, dap_list_length(l_list_used_out));
    log_it(L_WARNING, "tokens - %s", a_value_need->token_ticker);
    dap_list_t *l_item_out;
    DL_FOREACH(l_list_used_out, l_item_out) {
        dap_chain_tx_used_out_item_t *l_item = l_item_out->data;
        const char *l_coins_str, *l_value_str = dap_uint256_to_char(l_item->value, &l_coins_str);
        log_it(L_WARNING, "hash out - %s, num - %d, value - %s (%s)", dap_hash_fast_to_str_static(&l_item->tx_hash_fast),l_item->num_idx_out, l_value_str, l_coins_str);
        
    }

    if(!l_list_used_out) {
        log_it(L_WARNING, "Not enough funds in previous tx to transfer");
        if (a_jobj_errors) {
            dap_json_t *l_jobj_err = dap_json_object_new_string("Can't create in transaction. Not enough funds in previous tx "
                                                "to transfer");
            if (l_jobj_err)
                dap_json_array_add(a_jobj_errors, l_jobj_err);
        }
        // Go to the next item
        return -1;
    }   

    // add 'in' items
    uint256_t l_value_got = dap_chain_datum_tx_add_in_item_list(a_tx, l_list_used_out);
    assert(EQUAL_256(l_value_got, l_value_transfer));
    dap_list_free_full(l_list_used_out, free);
    if(!IS_ZERO_256(l_value_transfer)) {
        // add 'out' item for coin back
        uint256_t l_value_back;
        SUBTRACT_256_256(l_value_transfer, a_value_need->sum, &l_value_back);
        if(!IS_ZERO_256(l_value_back)) {
            dap_chain_datum_tx_add_out_ext_item(a_tx, a_addr_from, l_value_back, a_value_need->token_ticker);
            (*a_items_ready)++;
            return 0;
        }
    }
    return -1;
}


#define dap_chain_datum_tx_add_new_generic(a_tx, type, a_item) \
    ({ type* item = a_item; item ? ( dap_chain_datum_tx_add_item(a_tx, item), DAP_DELETE(item), 1 ) : -1; })

int dap_chain_net_tx_create_by_json(dap_json_t *a_tx_json, dap_chain_net_t *a_net, dap_json_t *a_json_obj_error,
                                        dap_chain_datum_tx_t** a_out_tx, size_t* a_items_count, size_t *a_items_ready)
{

    dap_json_t *l_json = a_tx_json;
    dap_json_t *l_jobj_errors = a_json_obj_error ? a_json_obj_error : NULL;

    if (!a_tx_json)
        return log_it(L_ERROR, "Empty json"), DAP_CHAIN_NET_TX_CREATE_JSON_CAN_NOT_OPEN_JSON_FILE;

    if(!a_out_tx){
        log_it(L_ERROR, "a_out_tx is NULL");
        return DAP_CHAIN_NET_TX_CREATE_JSON_WRONG_ARGUMENTS;
    }

    const char *l_native_token = a_net ? a_net->pub.native_ticker : NULL;
    const char *l_main_token = NULL;
    const char *l_token_reward = NULL;
    bool l_multichanel = false;

    bool l_stake = false;
    bool l_unstake = false;
    bool l_reward = false;

    // Read items from json file
    dap_json_t *l_json_items = NULL;

    dap_json_object_get_ex(l_json, "items", &l_json_items);
    size_t l_items_count;
    if(!l_json_items || !dap_json_is_array(l_json_items) || !(l_items_count = dap_json_array_length(l_json_items))) {
        dap_json_object_free(l_json);
        return DAP_CHAIN_NET_TX_CREATE_JSON_NOT_FOUNT_ARRAY_ITEMS;
    }

    log_it(L_NOTICE, "Json TX: found %lu items", l_items_count);
    // Create transaction
    dap_chain_datum_tx_t *l_tx = DAP_NEW_Z_SIZE(dap_chain_datum_tx_t, sizeof(dap_chain_datum_tx_t));
    if(!l_tx) {
        dap_json_object_free(l_json);
        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
    }

    int64_t l_ts_created = dap_json_object_get_int64(l_json, "ts_created");
    l_tx->header.ts_created = l_ts_created ? l_ts_created : time(NULL);

    size_t l_items_ready = 0;
    dap_list_t *l_in_list = NULL;// list 'in' items
    dap_list_t *l_sign_list = NULL;// list 'sign' items
    uint256_t l_value_need = { };// how many tokens are needed in the 'out' item
    uint256_t l_value_need_fee = {};
    uint256_t l_value_delegated	= {};
    uint256_t l_value_order_back = {};
    uint256_t l_value_reward = {};
    dap_chain_addr_t *l_addr_back = NULL;
    dap_chain_addr_t l_seller_addr = {};
    dap_sign_t *l_owner_sign = NULL;
    dap_chain_t * l_chain = NULL;
    dap_chain_addr_t *l_addr_reward = NULL;

    bool l_signed = false;

    for(int i = l_items_count - 1; i >= 0  && !l_signed; --i) {
        dap_json_t *l_json_item_obj = dap_json_array_get_idx(l_json_items, i);
        if(!l_json_item_obj || !dap_json_is_object(l_json_item_obj)) {
            continue;
        }   
        const char *l_item_type_str = dap_json_object_get_string(l_json_item_obj, "type");
        if(!l_item_type_str) {
            log_it(L_WARNING, "Item %du without type", i);
            continue;
        }
        l_signed |= TX_ITEM_TYPE_SIG == dap_chain_datum_tx_item_type_from_str_short(l_item_type_str);
    }

    if(a_net){ // if composition is not offline
        // First iteration in input file. Check the tx will be multichannel or not
        for(size_t i = 0; i < l_items_count; ++i) {
            dap_json_t *l_json_item_obj = dap_json_array_get_idx(l_json_items, i);
            if(!l_json_item_obj || !dap_json_is_object(l_json_item_obj)) {
                continue;
            }
             const char *l_item_type_str = dap_json_object_get_string(l_json_item_obj, "type");
             if(!l_item_type_str) {
                 log_it(L_WARNING, "Item %zu without type", i);
                 continue;
             }
            dap_chain_tx_item_type_t l_item_type = dap_chain_datum_tx_item_type_from_str_short(l_item_type_str);
            if(l_item_type == TX_ITEM_TYPE_UNKNOWN) {
                log_it(L_WARNING, "Item %zu has invalid type '%s'", i, l_item_type_str);
                continue;
            }

            switch (l_item_type) {
                case TX_ITEM_TYPE_IN: {
                    const char *l_json_item_token = s_json_get_text(l_json_item_obj, "token");
                    if (l_json_item_token && dap_strcmp(l_json_item_token, l_native_token)){
                        l_multichanel = true;
                        l_main_token = l_json_item_token;
                        break;
                    }
                    const char *l_prev_hash_str = s_json_get_text(l_json_item_obj, "prev_hash");
                    int64_t l_out_prev_idx;
                    bool l_is_out_prev_idx = s_json_get_int64_uint64(l_json_item_obj, "out_prev_idx", &l_out_prev_idx, false);
                    // If prev_hash and out_prev_idx were read
                    if(l_prev_hash_str && l_is_out_prev_idx){
                        dap_chain_hash_fast_t l_tx_prev_hash = {};
                        if(!dap_chain_hash_fast_from_str(l_prev_hash_str, &l_tx_prev_hash)) {
                            //check out token
                            dap_chain_datum_tx_t *l_prev_tx = dap_ledger_tx_find_by_hash(a_net->pub.ledger, &l_tx_prev_hash);
                            byte_t *l_prev_item = l_prev_tx ? dap_chain_datum_tx_item_get_nth(l_prev_tx, TX_ITEM_TYPE_OUT_ALL, l_out_prev_idx) : NULL;
                            if (l_prev_item){
                                const char* l_token = NULL;
                                if (*l_prev_item == TX_ITEM_TYPE_OUT){
                                    l_token = dap_ledger_tx_get_token_ticker_by_hash(a_net->pub.ledger, &l_tx_prev_hash);
                                } else if(*l_prev_item == TX_ITEM_TYPE_OUT_EXT){
                                    l_token = ((dap_chain_tx_out_ext_t*)l_prev_item)->token;
                                } else if (*l_prev_item == TX_ITEM_TYPE_OUT_STD) {
                                    l_token = ((dap_chain_tx_out_std_t *)l_prev_item)->token;
                                } else {
                                    log_it(L_WARNING, "Invalid 'in' item, wrong type of item with index %"DAP_UINT64_FORMAT_U" in previous tx %s", l_out_prev_idx, l_prev_hash_str);
                                    if (l_jobj_errors) {
                                        char *l_str_err = dap_strdup_printf("Unable to create in for transaction. Invalid 'in' item, "
                                                                            "wrong type of item with index %"DAP_UINT64_FORMAT_U" in previous tx %s", l_out_prev_idx, l_prev_hash_str);
                                        dap_json_t *l_jobj_err = dap_json_object_new_string(l_str_err);
                                        DAP_DELETE(l_str_err);
                                        if (l_jobj_err)
                                            dap_json_array_add(l_jobj_errors, l_jobj_err);
                                    }
                                    break;
                                }
                                if (dap_strcmp(l_token, l_native_token)){
                                    l_multichanel = true;
                                    l_main_token = l_json_item_token;
                                    break;
                                }

                            } else {
                                log_it(L_WARNING, "Invalid 'in' item, can't find item with index %"DAP_UINT64_FORMAT_U" in previous tx %s", l_out_prev_idx, l_prev_hash_str);
                                if (l_jobj_errors) {
                                    char *l_str_err = dap_strdup_printf("Unable to create in for transaction. Invalid 'in' item, "
                                                                        "can't find item with index %"DAP_UINT64_FORMAT_U" in previous tx %s", l_out_prev_idx, l_prev_hash_str);
                                    dap_json_t *l_jobj_err = dap_json_object_new_string(l_str_err);
                                    DAP_DELETE(l_str_err);
                                    if (l_jobj_err)
                                        dap_json_array_add(l_jobj_errors, l_jobj_err);
                                }
                            }
                        } else {
                            log_it(L_WARNING, "Invalid 'in' item, bad prev_hash %s", l_prev_hash_str);
                            if (l_jobj_errors) {
                                char *l_str_err = dap_strdup_printf("Unable to create in for transaction. Invalid 'in' item, "
                                                                    "bad prev_hash %s", l_prev_hash_str);
                                dap_json_t *l_jobj_err = dap_json_object_new_string(l_str_err);
                                DAP_DELETE(l_str_err);
                                if (l_jobj_err)
                                    dap_json_array_add(l_jobj_errors, l_jobj_err);
                            }
                        }
                    }
                }break;
                case TX_ITEM_TYPE_IN_COND: {
                    const char *l_prev_hash_str = s_json_get_text(l_json_item_obj, "prev_hash");
                    int64_t l_out_prev_idx;
                    char l_delegated_ticker_str[DAP_CHAIN_TICKER_SIZE_MAX] 	=	{};
                    bool l_is_out_prev_idx = s_json_get_int64_uint64(l_json_item_obj, "out_prev_idx", &l_out_prev_idx, false);
                    if(l_prev_hash_str && l_is_out_prev_idx){
                        dap_chain_hash_fast_t l_tx_prev_hash = {};
                        dap_chain_tx_out_cond_t	*l_tx_out_cond = NULL;
                        dap_chain_datum_token_t *l_delegated_token;
                        const char *l_ticker_str = NULL;
                        if(!dap_chain_hash_fast_from_str(l_prev_hash_str, &l_tx_prev_hash)) {
                            dap_chain_datum_tx_t *l_prev_tx = dap_ledger_tx_find_by_hash(a_net->pub.ledger, &l_tx_prev_hash);
                            l_ticker_str = dap_ledger_tx_get_token_ticker_by_hash(a_net->pub.ledger, &l_tx_prev_hash);
                            l_tx_out_cond = dap_chain_datum_tx_out_cond_get(l_prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK, NULL);
                            if (l_tx_out_cond && l_tx_out_cond->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK) {
                                //byte_t *l_prev_item = l_prev_tx ? dap_chain_datum_tx_item_get_nth(l_prev_tx, TX_ITEM_TYPE_OUT_ALL, l_out_prev_idx) : NULL;
                                dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker_str, l_ticker_str);
                                if (NULL != (l_delegated_token = dap_ledger_token_ticker_check(a_net->pub.ledger, l_delegated_ticker_str))){
                                    uint256_t l_emission_rate = dap_ledger_token_get_emission_rate(a_net->pub.ledger, l_delegated_ticker_str);
                                    //MULT_256_COIN(l_tx_out_cond->header.value, l_emission_rate, &l_value_delegated);
                                    SUM_256_256(l_value_delegated, l_tx_out_cond->header.value, &l_value_delegated);
                                }
                                l_main_token = l_ticker_str;
                                l_unstake = true;
                                l_multichanel = true;
                            }
                            /*
                            if (l_tx_out_cond->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE) {
                                SUM_256_256(l_value_order_back, l_tx_out_cond->header.value, &l_value_order_back);
                            }*/
                        }
                    }

                }break;
                case TX_ITEM_TYPE_IN_EMS: {
                    const char *l_emission_hash_str = s_json_get_text(l_json_item_obj, "emission_hash");
                    const char *l_json_item_token = s_json_get_text(l_json_item_obj, "token");
                    if (l_json_item_token){
                        if (dap_strcmp(l_json_item_token, l_native_token))//not native
                        {
                            if (l_emission_hash_str){//base tx
                                l_multichanel = true;
                                l_main_token = l_json_item_token;
                                break;
                            } else { //stake
                                l_stake = true; 
                                l_multichanel = true;
                            }                                 
                        }
                    }
                }break;
                case TX_ITEM_TYPE_SIG: {
                    dap_chain_wallet_t *l_wallet = s_json_get_wallet(l_json_item_obj, "wallet");
                    dap_chain_addr_t *l_wallet_addr = dap_chain_wallet_get_addr(l_wallet, a_net->pub.id);
                    l_seller_addr = *l_wallet_addr;
                     DAP_DELETE(l_wallet_addr);
                    if (l_wallet)
                        dap_chain_wallet_close(l_wallet);

                }break;
                case TX_ITEM_TYPE_IN_REWARD:{
                    uint256_t l_value = { };
                    bool l_is_value = s_json_get_uint256(l_json_item_obj, "value", &l_value);
                    if (!l_is_value) {
                        l_chain = dap_chain_net_get_default_chain_by_chain_type(a_net, CHAIN_TYPE_TX);
                    }
                    l_reward = true;
                    break;
                }                
                default: continue;
            }
            //if(l_multichanel)
                //break;
        }
    }

    // Creating and adding items to the transaction
    for(size_t i = 0; i < l_items_count; ++i) {
        dap_json_t *l_json_item_obj = dap_json_array_get_idx(l_json_items, i);
        if(!l_json_item_obj || !dap_json_is_object(l_json_item_obj)) {
            continue;
        }
        const char *l_item_type_str = dap_json_object_get_string(l_json_item_obj, "type");
        if(!l_item_type_str) {
            log_it(L_WARNING, "Item %zu without type", i);
            continue;
        }
        dap_chain_tx_item_type_t l_item_type = dap_chain_datum_tx_item_type_from_str_short(l_item_type_str);
        if(l_item_type == TX_ITEM_TYPE_UNKNOWN) {
            log_it(L_WARNING, "Item %zu has invalid type '%s'", i, l_item_type_str);
            continue;
        }

        log_it(L_DEBUG, "Json TX: process item %s", l_item_type_str);
        // Create an item depending on its type
        uint8_t *l_item = NULL;
        switch (l_item_type) {

        case TX_ITEM_TYPE_EVENT: {
            const char *l_group_name = s_json_get_text(l_json_item_obj, "group_name");
            if (!l_group_name) {
                log_it(L_ERROR, "Json TX: bad group_name in TX_ITEM_TYPE_EVENT");
                if (l_jobj_errors) {
                    char *l_str_err = dap_strdup_printf("For item %zu of type 'event' the 'group_name' is missing.", i);
                    dap_json_t *l_jobj_err = dap_json_object_new_string(l_str_err);
                    DAP_DELETE(l_str_err);
                    if (l_jobj_err)
                        dap_json_array_add(l_jobj_errors, l_jobj_err);
                }
                break;
            }

            int64_t l_event_type_int;
            if (!s_json_get_int64_uint64(l_json_item_obj, "event_type", &l_event_type_int, false)) {
                log_it(L_ERROR, "Json TX: bad event_type in TX_ITEM_TYPE_EVENT");
                if (l_jobj_errors) {
                    char *l_str_err = dap_strdup_printf("For item %zu of type 'event' the 'event_type' is missing or invalid.", i);
                    dap_json_t *l_jobj_err = dap_json_object_new_string(l_str_err);
                    DAP_DELETE(l_str_err);
                    if (l_jobj_err)
                        dap_json_array_add(l_jobj_errors, l_jobj_err);
                }
                break;
            }

            uint64_t l_srv_uid;
            if (!s_json_get_srv_uid(l_json_item_obj, "service_id", "service", &l_srv_uid)) {
                log_it(L_ERROR, "Json TX: bad srv_uid in TX_ITEM_TYPE_EVENT");
                if (l_jobj_errors) {
                    char *l_str_err = dap_strdup_printf("For item %zu of type 'event' the 'srv_uid' is missing or invalid.", i);
                    dap_json_t *l_jobj_err = dap_json_object_new_string(l_str_err);
                    DAP_DELETE(l_str_err);
                    if (l_jobj_err)
                        dap_json_array_add(l_jobj_errors, l_jobj_err);
                }
                break;
            }

            dap_chain_tx_item_event_t *l_event_item = dap_chain_datum_tx_event_create((dap_chain_srv_uid_t){.uint64 = l_srv_uid},
                                                                                       l_group_name, (uint16_t)l_event_type_int, dap_time_now());
            if (!l_event_item) {
                if (l_jobj_errors) {
                    char *l_str_err = dap_strdup_printf("Unable to create event item for transaction from item %zu.", i);
                    dap_json_t *l_jobj_err = dap_json_object_new_string(l_str_err);
                    DAP_DELETE(l_str_err);
                    if (l_jobj_err)
                        dap_json_array_add(l_jobj_errors, l_jobj_err);
                }
            }
            l_item = (uint8_t *) l_event_item;
            break;
        }

        case TX_ITEM_TYPE_IN: {
            // Save item obj for in
            // Read prev_hash and out_prev_idx
            const char *l_prev_hash_str = s_json_get_text(l_json_item_obj, "prev_hash");
            int64_t l_out_prev_idx;
            bool l_is_out_prev_idx = s_json_get_int64_uint64(l_json_item_obj, "out_prev_idx", &l_out_prev_idx, false);
            // If prev_hash and out_prev_idx were read
            if(l_prev_hash_str && l_is_out_prev_idx) {
                dap_chain_hash_fast_t l_tx_prev_hash;
                if(!dap_chain_hash_fast_from_str(l_prev_hash_str, &l_tx_prev_hash)) {
                    // Create IN item
                    dap_chain_tx_in_t *l_in_item = dap_chain_datum_tx_item_in_create(&l_tx_prev_hash, (uint32_t) l_out_prev_idx);
                    if (!l_in_item) {
                        if (l_jobj_errors) {
                            dap_json_t *l_jobj_err = dap_json_object_new_string("Unable to create in for transaction.");
                            if (l_jobj_err)
                                dap_json_array_add(l_jobj_errors, l_jobj_err);
                        }
                    }
                    l_item = (uint8_t *)l_in_item;
                } else {
                    log_it(L_WARNING, "Invalid 'in' item, bad prev_hash %s", l_prev_hash_str);
                    if (l_jobj_errors) {
                        char *l_str_err = dap_strdup_printf("Unable to create in for transaction. Invalid 'in' item, "
                                                            "bad prev_hash %s", l_prev_hash_str);
                        dap_json_t *l_jobj_err = dap_json_object_new_string(l_str_err);
                        DAP_DELETE(l_str_err);
                        if (l_jobj_err)
                            dap_json_array_add(l_jobj_errors, l_jobj_err);
                    }
                }
            }
            // Read addr_from
            else {
                if (l_unstake) {
                    const char *l_json_item_addr_str = s_json_get_text(l_json_item_obj, "addr_from");
                    if (l_json_item_addr_str)
                        l_addr_back = dap_chain_addr_from_str(l_json_item_addr_str);
                }
                l_in_list = dap_list_append(l_in_list, l_json_item_obj);
            }
        }
        break;
        case TX_ITEM_TYPE_IN_COND: {
            const char *l_prev_hash_str = s_json_get_text(l_json_item_obj, "prev_hash");
            int64_t l_out_prev_idx;
            bool l_is_out_prev_idx = s_json_get_int64_uint64(l_json_item_obj, "out_prev_idx", &l_out_prev_idx, false);
            if(l_prev_hash_str && l_is_out_prev_idx){
                dap_chain_hash_fast_t l_tx_prev_hash = {};
                dap_chain_tx_out_cond_t	*l_tx_out_cond = NULL;
                if(!dap_chain_hash_fast_from_str(l_prev_hash_str, &l_tx_prev_hash)) {
                    //check out token
                    dap_chain_datum_tx_t *l_prev_tx = dap_ledger_tx_find_by_hash(a_net->pub.ledger, &l_tx_prev_hash);
                    l_tx_out_cond = dap_chain_datum_tx_out_cond_get(l_prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK, NULL);
                    byte_t *l_prev_item = l_prev_tx ? dap_chain_datum_tx_item_get_nth(l_prev_tx, TX_ITEM_TYPE_OUT_ALL, l_out_prev_idx) : NULL;
                    if (l_tx_out_cond && l_tx_out_cond->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK) {
                        dap_chain_tx_in_cond_t * l_in_cond = dap_chain_datum_tx_item_in_cond_create(&l_tx_prev_hash, l_out_prev_idx, 0);
                        l_item = (uint8_t *)l_in_cond;

                        if (l_prev_item){
                            if (*l_prev_item == TX_ITEM_TYPE_OUT_COND){
                                //dap_chain_tx_in_cond_t * l_in_cond = dap_chain_datum_tx_item_in_cond_create(&l_tx_prev_hash, l_out_prev_idx, 0);
                                //l_item = (uint8_t *)l_in_cond;                            
                            } else {
                                log_it(L_WARNING, "Invalid 'in_cond' item, wrong type of item with index %"DAP_UINT64_FORMAT_U" in previous tx %s", l_out_prev_idx, l_prev_hash_str);
                                if (l_jobj_errors) {
                                    char *l_str_err = dap_strdup_printf("Unable to create in for transaction. Invalid 'in_cond' item, "
                                                                        "wrong type of item with index %"DAP_UINT64_FORMAT_U" in previous tx %s", l_out_prev_idx, l_prev_hash_str);
                                    dap_json_t *l_jobj_err = dap_json_object_new_string(l_str_err);
                                    DAP_DELETE(l_str_err);
                                    if (l_jobj_err)
                                        dap_json_array_add(l_jobj_errors, l_jobj_err);
                                }
                                break;
                            }                                                         
                        } else {
                            log_it(L_WARNING, "Invalid 'in_cond' item, can't find item with index %"DAP_UINT64_FORMAT_U" in previous tx %s", l_out_prev_idx, l_prev_hash_str);
                            if (l_jobj_errors) {
                                char *l_str_err = dap_strdup_printf("Unable to create in for transaction. Invalid 'in_cond' item, "
                                                                    "can't find item with index %"DAP_UINT64_FORMAT_U" in previous tx %s", l_out_prev_idx, l_prev_hash_str);
                                dap_json_t *l_jobj_err = dap_json_object_new_string(l_str_err);
                                DAP_DELETE(l_str_err);
                                if (l_jobj_err)
                                    dap_json_array_add(l_jobj_errors, l_jobj_err);
                            }
                        }  
                    }
                    l_tx_out_cond = dap_chain_datum_tx_out_cond_get(l_prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE, NULL);
                    if (l_tx_out_cond && l_tx_out_cond->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE) {
                        dap_chain_tx_in_cond_t * l_in_cond = dap_chain_datum_tx_item_in_cond_create(&l_tx_prev_hash, l_out_prev_idx, 0);
                        l_item = (uint8_t *)l_in_cond;
                    }                   
                } else {
                    log_it(L_WARNING, "Invalid 'in_cond' item, bad prev_hash %s", l_prev_hash_str);
                    if (l_jobj_errors) {
                        char *l_str_err = dap_strdup_printf("Unable to create in for transaction. Invalid 'in_cond' item, "
                                                            "bad prev_hash %s", l_prev_hash_str);
                        dap_json_t *l_jobj_err = dap_json_object_new_string(l_str_err);
                        DAP_DELETE(l_str_err);
                        if (l_jobj_err)
                            dap_json_array_add(l_jobj_errors, l_jobj_err);
                    }
                }
            }
        }break;
        case TX_ITEM_TYPE_IN_EMS:{
            int64_t l_chain_id_uint;
            bool l_is_chain_id = s_json_get_int64_uint64(l_json_item_obj, "chain_id", &l_chain_id_uint, false);
            dap_chain_id_t l_chain_id = { .uint64 = l_chain_id_uint };
            const char *l_json_item_token = s_json_get_text(l_json_item_obj, "token");
            if (l_json_item_token && l_is_chain_id){
                dap_hash_fast_t l_blank_hash = {};
                dap_chain_tx_in_ems_t *l_in_ems = dap_chain_datum_tx_item_in_ems_create(l_chain_id, &l_blank_hash, l_json_item_token);
                l_item = (uint8_t *)l_in_ems;
            } else {
                char *l_str_err = NULL;
                if (!l_is_chain_id) {
                    log_it(L_WARNING, "Invalid 'in_ems' item, can't read chain_id");
                    l_str_err = dap_strdup_printf("Unable to create in for transaction. Invalid 'in_ems' item, can't read chain_id");
                }
                if (!l_json_item_token){
                    log_it(L_WARNING, "Invalid 'in_ems' item, bad token");
                    l_str_err = dap_strdup_printf("Unable to create in for transaction. Invalid 'in_ems' item, bad token");
                }
                dap_json_t *l_jobj_err = dap_json_object_new_string(l_str_err);
                if (l_jobj_errors) dap_json_array_add(l_jobj_errors, l_jobj_err);
            }
        } break;

        case TX_ITEM_TYPE_IN_REWARD:{
            uint256_t l_value = { };
            dap_chain_block_cache_t *l_block_cache = NULL;
            //dap_chain_hash_fast_t l_block_hash={0};
            const char *l_block_hash_str = s_json_get_text(l_json_item_obj, "block_hash");
            bool l_is_value = s_json_get_uint256(l_json_item_obj, "value", &l_value);
            if(l_block_hash_str ) {
                dap_hash_fast_t l_block_hash;
                if(l_is_value && !dap_chain_hash_fast_from_str(l_block_hash_str, &l_block_hash)) {
                    if (l_is_value)
                        SUM_256_256(l_value_reward, l_value, &l_value_reward);
                    else if (l_chain) {
                        l_block_cache = dap_chain_block_cache_get_by_hash(DAP_CHAIN_TYPE_BLOCKS(l_chain), &l_block_hash);
                        dap_sign_t *l_sign = dap_chain_block_sign_get(l_block_cache->block, l_block_cache->block_size, 0);
                        dap_pkey_t * l_block_sign_pkey = dap_pkey_get_from_sign(l_sign);
                        l_value = l_chain->callback_calc_reward(l_chain, &l_block_hash,l_block_sign_pkey);
                        SUM_256_256(l_value_reward, l_value, &l_value_reward);
                    }                    
                    dap_chain_tx_in_reward_t *l_in_reward = dap_chain_datum_tx_item_in_reward_create(&l_block_hash);
                    l_item = (uint8_t *)l_in_reward;
                } else {
                    log_it(L_WARNING, "Invalid 'in_reward' item, bad block_hash %s", l_block_hash_str);
                    char *l_str_err = dap_strdup_printf("Unable to create in for transaction. Invalid 'in_reward' item, "
                                                        "bad block_hash %s", l_block_hash_str);
                    dap_json_t *l_jobj_err = dap_json_object_new_string(l_str_err);
                    if (l_jobj_errors) dap_json_array_add(l_jobj_errors, l_jobj_err);
                }
            }

        } break;      

        case TX_ITEM_TYPE_OUT:
        case TX_ITEM_TYPE_OUT_EXT:
        case TX_ITEM_TYPE_OUT_STD: {
            // Read address and value
            uint256_t l_value = { };
            const char *l_json_item_addr_str = s_json_get_text(l_json_item_obj, "addr");
            const char *l_json_item_addr_to_str = s_json_get_text(l_json_item_obj, "addr_to");
            bool l_is_value = s_json_get_uint256(l_json_item_obj, "value", &l_value);
            const char *l_token = s_json_get_text(l_json_item_obj, "token");
            if (l_is_value && (l_json_item_addr_str || l_json_item_addr_to_str)) {
                dap_chain_addr_t *l_addr = dap_chain_addr_from_str(l_json_item_addr_str);
                if((l_json_item_addr_to_str || l_addr) && !IS_ZERO_256(l_value)) {
                    if(l_item_type == TX_ITEM_TYPE_OUT) {
                        // Create OUT item
                        uint8_t *l_out_item = NULL;
                        if (l_unstake){
                            l_out_item = (uint8_t *)dap_chain_datum_tx_item_out_ext_create(l_addr, l_value, l_token);
                            l_item = (uint8_t *)l_out_item;
                            SUBTRACT_256_256(l_value_delegated, l_value, &l_value_delegated);
                            break;
                        }
                        if (a_net && !l_signed) {// if composition is not offline
                            if (l_multichanel) {
                                if ( l_stake && dap_strcmp(l_token, l_native_token)){//not native
                                    l_out_item = (uint8_t *)dap_chain_datum_tx_item_out_ext_create(l_addr, l_value, l_token);
                                    l_item = (uint8_t *)l_out_item;
                                    break;
                                }
                                else
                                    l_out_item = (uint8_t *)dap_chain_datum_tx_item_out_std_create(l_addr, l_value, l_token ? l_token : (l_main_token ? l_main_token : l_native_token), 0);
                            }
                            else
                                l_out_item = (uint8_t *)dap_chain_datum_tx_item_out_ext_create(l_addr, l_value, l_native_token);
                            if (!l_out_item) {
                                dap_json_t *l_jobj_err = dap_json_object_new_string("Failed to create transaction out. "
                                                                                "There may not be enough funds in the wallet.");
                                if (l_jobj_errors) dap_json_array_add(l_jobj_errors, l_jobj_err);
                            }
                            if (l_out_item){
                                if (l_multichanel && !dap_strcmp(((dap_chain_tx_out_std_t *)l_out_item)->token, l_native_token))
                                    SUM_256_256(l_value_need_fee, l_value, &l_value_need_fee);
                                else
                                    SUM_256_256(l_value_need, l_value, &l_value_need);
                            }
                        } else {
                            if (!l_signed)
                                l_out_item = (uint8_t *)dap_chain_datum_tx_item_out_ext_create(l_addr, l_value, l_token);
                            else
                                l_out_item = (uint8_t *)dap_chain_datum_tx_item_out_create(l_addr, l_value);
                            if (!l_out_item) {
                                dap_json_t *l_jobj_err = dap_json_object_new_string("Failed to create transaction out. "
                                                                                "There may not be enough funds in the wallet.");
                                if (l_jobj_errors) dap_json_array_add(l_jobj_errors, l_jobj_err);
                            }
                        }
                        l_item = (uint8_t *)l_out_item;
                    } else if ( l_item_type == TX_ITEM_TYPE_OUT_EXT || l_item_type == TX_ITEM_TYPE_OUT_STD ) {
                        // Read address and value
                        if (l_unstake && l_is_value && !dap_strcmp(l_json_item_addr_to_str, "NULL")){
                            uint8_t *l_out_item = NULL;
                            l_out_item = (uint8_t *)dap_chain_datum_tx_item_out_ext_create(&c_dap_chain_addr_blank_1, l_value, l_token);
                            if (l_out_item){
                                SUM_256_256(l_value_need, l_value, &l_value_need);
                            }
                            l_item = (uint8_t *)l_out_item;
                            break;
                        }
                        if (l_reward && l_is_value) {
                            uint8_t *l_out_item = NULL;
                            SUBTRACT_256_256(l_value_reward, l_value, &l_value_reward);
                            l_out_item = (uint8_t *)dap_chain_datum_tx_item_out_ext_create(l_addr, l_value, l_token);
                            l_item = (uint8_t *)l_out_item;
                            break;
                        }
                        if (l_token) {
                            // Create OUT_EXT item
                            uint8_t *l_out_item = NULL;
                            if (a_net){ // if composition is not offline
                                if (!l_signed) {
                                    if(l_multichanel)
                                        l_out_item = (uint8_t *)dap_chain_datum_tx_item_out_std_create(l_addr, l_value, l_token, 0);
                                    else
                                        l_out_item = (uint8_t *)dap_chain_datum_tx_item_out_create(l_addr, l_value);
                                } else {
                                    if (l_item_type == TX_ITEM_TYPE_OUT_EXT)
                                        l_out_item = (uint8_t *)dap_chain_datum_tx_item_out_ext_create(l_addr, l_value, l_token);
                                    else
                                        l_out_item = (uint8_t *)dap_chain_datum_tx_item_out_std_create(l_addr, l_value, l_token, 0);
                                }
                                if (!l_out_item) {
                                    dap_json_t *l_jobj_err = dap_json_object_new_string("Failed to create a out ext"
                                                                        "for a transaction. There may not be enough funds "
                                                                        "on the wallet or the wrong ticker token "
                                                                        "is indicated.");
                                    if (l_jobj_errors) dap_json_array_add(l_jobj_errors, l_jobj_err);
                                }
                                if (l_out_item){
                                    if (l_multichanel && !dap_strcmp(l_token, l_native_token))
                                        SUM_256_256(l_value_need_fee, l_value, &l_value_need_fee);
                                    else
                                        SUM_256_256(l_value_need, l_value, &l_value_need);
                                }
                            } else {
                                if (!l_signed || l_item_type == TX_ITEM_TYPE_OUT_STD) {
                                    l_out_item = (uint8_t *)dap_chain_datum_tx_item_out_std_create(l_addr, l_value, l_token, 0);
                                } else {
                                    l_out_item = (uint8_t *)dap_chain_datum_tx_item_out_ext_create(l_addr, l_value, l_token);
                                }
                                if (!l_out_item) {
                                    dap_json_t *l_jobj_err = dap_json_object_new_string("Failed to create a out ext"
                                                                        "for a transaction. There may not be enough funds "
                                                                        "on the wallet or the wrong ticker token "
                                                                        "is indicated.");
                                    if (l_jobj_errors) dap_json_array_add(l_jobj_errors, l_jobj_err);
                                }
                            }
                            l_item = (uint8_t *)l_out_item;
                        }
                        else {
                            log_it(L_WARNING, "Invalid 'out_ext' item %zu", i);
                            continue;
                        }
                    }
                } else {
                    log_it(L_WARNING, "Invalid 'out%s' item %zu",
                                      l_item_type == TX_ITEM_TYPE_OUT_STD ? "_std" : (l_item_type == TX_ITEM_TYPE_OUT_EXT ? "_ext" : ""), i);
                    char *l_str_err = dap_strdup_printf("For item %zu of type 'out', 'out_ext' or 'out_std' the "
                                                        "string representation of the address could not be converted, "
                                                        "or the size of the output sum is 0.", i);
                    dap_json_t *l_jobj_err = dap_json_object_new_string(l_str_err);
                    DAP_DELETE(l_str_err);
                    if (l_jobj_errors) dap_json_array_add(l_jobj_errors, l_jobj_err);
                    continue;
                }
            } else if (l_json_item_addr_to_str && l_token) {
                l_addr_reward = dap_chain_addr_from_str(l_json_item_addr_to_str);
                l_token_reward = l_token;
            }
        }
            break;
        case TX_ITEM_TYPE_OUT_COND: {
            // Read subtype of item
            const char *l_subtype_str = s_json_get_text(l_json_item_obj, "subtype");
            dap_chain_tx_out_cond_subtype_t l_subtype = dap_chain_tx_out_cond_subtype_from_str_short(l_subtype_str);
            switch (l_subtype) {

            case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY:{
                uint256_t l_value = { };
                bool l_is_value = s_json_get_uint256(l_json_item_obj, "value", &l_value);
                if(!l_is_value || IS_ZERO_256(l_value)) {
                    log_it(L_ERROR, "Json TX: bad value in OUT_COND_SUBTYPE_SRV_PAY");
                    break;
                }
                uint256_t l_value_max_per_unit = { };
                l_is_value = s_json_get_uint256(l_json_item_obj, "value_max_per_unit", &l_value_max_per_unit);
                if(!l_is_value || IS_ZERO_256(l_value_max_per_unit)) {
                    log_it(L_ERROR, "Json TX: bad value_max_per_unit in OUT_COND_SUBTYPE_SRV_PAY");
                    break;
                }
                dap_chain_net_srv_price_unit_uid_t l_price_unit;
                if(!s_json_get_unit(l_json_item_obj, "price_unit", &l_price_unit)) {
                    log_it(L_ERROR, "Json TX: bad price_unit in OUT_COND_SUBTYPE_SRV_PAY");
                    break;
                }
                uint64_t l_srv_uid = 0;
                if(!s_json_get_srv_uid(l_json_item_obj, "service_id", "service", &l_srv_uid)){
                    // Default service DAP_CHAIN_NET_SRV_VPN_ID
                    l_srv_uid = 0x0000000000000001;
                }

                // From "wallet" or "cert"
                dap_pkey_t *l_pkey = s_json_get_pkey(l_json_item_obj);
                if(!l_pkey) {
                    log_it(L_ERROR, "Json TX: bad pkey in OUT_COND_SUBTYPE_SRV_PAY");
                    break;
                }
                const char *l_params_str = s_json_get_text(l_json_item_obj, "params");
                size_t l_params_size = dap_strlen(l_params_str);
                dap_chain_tx_out_cond_t *l_out_cond_item = dap_chain_datum_tx_item_out_cond_create_srv_pay(l_pkey, (dap_chain_srv_uid_t){.uint64 = l_srv_uid},
                                                                                                           l_value, l_value_max_per_unit,
                        l_price_unit, l_params_str, l_params_size);
                l_item = (uint8_t *)l_out_cond_item;
                // Save value for using in In item
                if(l_item) {
                    if (l_reward)
                        SUBTRACT_256_256(l_value_reward, l_value, &l_value_reward);
                    else
                        SUM_256_256(l_value_need, l_value, &l_value_need);
                } else {
                    char *l_str_err = dap_strdup_printf("Unable to create conditional out for transaction "
                                                        "can of type %s described in item %zu.\n", l_subtype_str, i);
                    dap_json_t *l_jobj_err = dap_json_object_new_string(l_str_err);
                    DAP_DELETE(l_str_err);
                    if (l_jobj_errors) dap_json_array_add(l_jobj_errors, l_jobj_err);
                }
                DAP_DELETE(l_pkey);
            }
                break;
            case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE: {

                uint64_t l_srv_uid = 0;
                if(!s_json_get_srv_uid(l_json_item_obj, "service_id", "service", &l_srv_uid))
                    // Default service DAP_CHAIN_NET_SRV_XCHANGE_ID
                    l_srv_uid = 0x2;
                dap_chain_net_t *l_net = dap_chain_net_by_name(s_json_get_text(l_json_item_obj, "net"));
                if(!l_net) {
                    log_it(L_ERROR, "Json TX: bad net in OUT_COND_SUBTYPE_SRV_XCHANGE");
                    break;
                }
                const char *l_token_buy = s_json_get_text(l_json_item_obj, "token_buy");
                if(!l_token_buy) {
                    log_it(L_ERROR, "Json TX: bad token_buy in OUT_COND_SUBTYPE_SRV_XCHANGE");
                    break;
                }
                uint256_t l_value = { };
                if(!s_json_get_uint256(l_json_item_obj, "value", &l_value) || IS_ZERO_256(l_value)) {
                    log_it(L_ERROR, "Json TX: bad value in OUT_COND_SUBTYPE_SRV_XCHANGE");
                    break;
                }
                uint256_t l_value_rate = { };
                if(!s_json_get_uint256(l_json_item_obj, "rate", &l_value_rate) || IS_ZERO_256(l_value_rate)) {
                    log_it(L_ERROR, "Json TX: bad value rate in OUT_COND_SUBTYPE_SRV_XCHANGE");
                    break;
                }
                //const char *l_params_str = s_json_get_text(l_json_item_obj, "params");
                //size_t l_params_size = dap_strlen(l_params_str);
                dap_chain_tx_out_cond_t *l_out_cond_item = dap_chain_datum_tx_item_out_cond_create_srv_xchange((dap_chain_srv_uid_t){.uint64 = l_srv_uid}, l_net->pub.id,
                                                                                                                l_value, l_net->pub.id,
                                                                                                                l_token_buy, l_value_rate,
                                                                                                                &l_seller_addr,
                                                                                                                NULL, 0);
                l_item = (uint8_t *)l_out_cond_item;
                // Save value for using in In item
                if(l_item) {
                    SUM_256_256(l_value_need, l_value, &l_value_need);
                } else {
                    char *l_str_err = dap_strdup_printf("Unable to create conditional out for transaction "
                                                         "can of type %s described in item %zu.", l_subtype_str, i);
                    dap_json_t *l_jobj_err = dap_json_object_new_string(l_str_err);
                    DAP_DELETE(l_str_err);
                    if (l_jobj_errors) dap_json_array_add(l_jobj_errors, l_jobj_err);
                }
            }
                break;
            case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK:{
                uint64_t l_srv_uid = 0;
                if(!s_json_get_srv_uid(l_json_item_obj, "service_id", "service", &l_srv_uid)){
                    // Default service DAP_CHAIN_NET_SRV_VPN_ID
                    l_srv_uid = 0x12;
                }
                uint256_t l_value = { };
                if(!s_json_get_uint256(l_json_item_obj, "value", &l_value) || IS_ZERO_256(l_value)) {
                    log_it(L_ERROR, "Json TX: bad value in DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK");
                    break;
                }
                const char* l_time_staking_str = NULL;
                if((l_time_staking_str = s_json_get_text(l_json_item_obj, "time_staking")) == NULL || dap_strlen(l_time_staking_str) != 6)  {
                    log_it(L_ERROR, "Json TX: bad time staking in DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK");
                    break;
                }

                char l_time_staking_month_str[3] = {l_time_staking_str[2], l_time_staking_str[3], 0};
                int l_time_staking_month = atoi(l_time_staking_month_str);
                if (l_time_staking_month < 1 || l_time_staking_month > 12){
                    log_it(L_ERROR, "Json TX: bad time staking in DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK");
                    break;
                }


                char l_time_staking_day_str[3] = {l_time_staking_str[4], l_time_staking_str[5], 0};
                int l_time_staking_day = atoi(l_time_staking_day_str);
                if (l_time_staking_day < 1 || l_time_staking_day > 31){
                    log_it(L_ERROR, "Json TX: bad time staking in DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK");
                    break;
                }

                dap_time_t l_time_staking = 0;
                l_time_staking = dap_time_from_str_simplified(l_time_staking_str);
                if (0 == l_time_staking){
                    log_it(L_ERROR, "Json TX: bad time staking in DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK");
                    break;
                }
                dap_time_t l_time_now = dap_time_now();
                if (l_time_staking < l_time_now){
                    log_it(L_ERROR, "Json TX: bad time staking in DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK");
                    break;
                }
                l_time_staking -= l_time_now;

                uint256_t l_reinvest_percent = uint256_0;
                const char* l_reinvest_percent_str = NULL;
                if((l_reinvest_percent_str = s_json_get_text(l_json_item_obj, "reinvest_percent"))!=NULL) {
                    l_reinvest_percent = dap_uint256_scan_decimal(l_reinvest_percent_str);
                    if (compare256(l_reinvest_percent, dap_uint256_scan_decimal("100.0")) == 1){
                    log_it(L_ERROR, "Json TX: bad reinvest percent in DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK");
                        break;
                    }
                    if (IS_ZERO_256(l_reinvest_percent)) {
                        int l_reinvest_percent_int = atoi(l_reinvest_percent_str);
                        if (l_reinvest_percent_int < 0 || l_reinvest_percent_int > 100){
                            log_it(L_ERROR, "Json TX: bad reinvest percent in DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK");
                            break;
                        }
                        l_reinvest_percent = dap_chain_uint256_from(l_reinvest_percent_int);
                        MULT_256_256(l_reinvest_percent, GET_256_FROM_64(1000000000000000000ULL), &l_reinvest_percent);
                    }
                }

                dap_chain_tx_out_cond_t *l_out_cond_item = dap_chain_datum_tx_item_out_cond_create_srv_stake_lock((dap_chain_srv_uid_t){.uint64 = l_srv_uid}, l_value, l_time_staking, l_reinvest_percent);
                l_item = (uint8_t *)l_out_cond_item;
                // Save value for using in In item
                if(l_item) {
                    SUM_256_256(l_value_need, l_value, &l_value_need);
                } else {
                    char *l_str_err = dap_strdup_printf("Unable to create conditional out for transaction "
                                                         "can of type %s described in item %zu.", l_subtype_str, i);
                    dap_json_t *l_jobj_err = dap_json_object_new_string(l_str_err);
                    DAP_DELETE(l_str_err);
                    if (l_jobj_errors) dap_json_array_add(l_jobj_errors, l_jobj_err);
                }
            }
                break;
            case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE:{
                uint64_t l_srv_uid = 0;
                if(!s_json_get_srv_uid(l_json_item_obj, "service_id", "service", &l_srv_uid)) {
                    // Default service DAP_CHAIN_NET_SRV_STAKE_ID
                    l_srv_uid = 0x13;
                }
                uint256_t l_value = { };
                if(!s_json_get_uint256(l_json_item_obj, "value", &l_value) || IS_ZERO_256(l_value)) {
                    log_it(L_ERROR, "Json TX: bad value in OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE");
                    break;
                }
                uint256_t l_fee_value = { };
                if(!s_json_get_uint256(l_json_item_obj, "fee", &l_fee_value) || IS_ZERO_256(l_fee_value)) {
                    break;
                }

                const char *l_signing_addr_str = s_json_get_text(l_json_item_obj, "signing_addr");
                dap_chain_addr_t *l_signing_addr = dap_chain_addr_from_str(l_signing_addr_str);
                if(!l_signing_addr) {
                    log_it(L_ERROR, "Json TX: bad signing_addr in OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE");
                    break;
                }                
                const char *l_pkey_full_str = s_json_get_text(l_json_item_obj, "pkey_full");
                dap_pkey_t *l_pkey = dap_pkey_get_from_str(l_pkey_full_str);
                if(!l_pkey) {
                    log_it(L_ERROR, "Json TX: bad pkey_full in OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE");
                    break;
                }
                dap_hash_fast_t l_pkey_hash = { };
                if (!dap_pkey_get_hash(l_pkey, &l_pkey_hash) || memcmp(&l_pkey_hash, &l_signing_addr->data.hash_fast, sizeof(l_pkey_hash))) {
                    log_it(L_ERROR, "Json TX: signing_addr it's not a derivative pkey_full in OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE");
                    break;
                }

                dap_chain_node_addr_t l_signer_node_addr;
                const char *l_node_addr_str = s_json_get_text(l_json_item_obj, "node_addr");
                if(!l_node_addr_str || dap_chain_node_addr_from_str(&l_signer_node_addr, l_node_addr_str)) {
                    log_it(L_ERROR, "Json TX: bad node_addr in OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE");
                    break;
                }

                dap_chain_tx_out_cond_t *l_out_cond_item = dap_chain_datum_tx_item_out_cond_create_srv_stake((dap_chain_srv_uid_t){.uint64 = l_srv_uid}, l_value, l_signing_addr,
                                                                                                             &l_signer_node_addr, NULL, uint256_0, l_pkey);
                DAP_DEL_MULTY(l_pkey, l_signing_addr);
                l_item = (uint8_t *)l_out_cond_item;
                // Save value for using in In item
                if(l_item) {
                    SUM_256_256(l_value_need, l_value, &l_value_need);
                } else {
                    char *l_err_str = dap_strdup_printf("Unable to create conditional out for transaction "
                                                        "can of type %s described in item %zu.", l_subtype_str, i);
                    dap_json_t *l_jobj_err = dap_json_object_new_string(l_err_str);
                    DAP_DELETE(l_err_str);
                    if (l_jobj_errors)
                        dap_json_array_add(l_jobj_errors, l_jobj_err);
                }
            }
                break;
            case DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE: {
                uint256_t l_value = { };
                s_json_get_uint256(l_json_item_obj, "value", &l_value);
                if(!IS_ZERO_256(l_value)) {
                    if (l_unstake){
                        dap_chain_tx_out_cond_t *l_out_cond_item = dap_chain_datum_tx_item_out_cond_create_fee(l_value);
                        l_item = (uint8_t *)l_out_cond_item;
                        SUBTRACT_256_256(l_value_delegated, l_value, &l_value_delegated);
                        break;
                    }
                    dap_chain_tx_out_cond_t *l_out_cond_item = dap_chain_datum_tx_item_out_cond_create_fee(l_value);
                    l_item = (uint8_t *)l_out_cond_item;
                    // Save value for using in In item
                    if(l_item) {
                        SUM_256_256(l_value_need_fee, l_value, &l_value_need_fee);
                    } else {
                        char *l_str_err = dap_strdup_printf("Unable to create conditional out for transaction "
                                                            "can of type %s described in item %zu.", l_subtype_str, i);
                        dap_json_t *l_jobj_err = dap_json_object_new_string(l_str_err);
                        if (l_jobj_errors) dap_json_array_add(l_jobj_errors, l_jobj_err);
                        DAP_DELETE(l_str_err);
                    }
                }
                else
                    log_it(L_ERROR, "Json TX: zero value in OUT_COND_SUBTYPE_FEE");
            } break;
            
            case DAP_CHAIN_TX_OUT_COND_SUBTYPE_WALLET_SHARED: {
                uint256_t l_value = { };
                if(!s_json_get_uint256(l_json_item_obj, "value", &l_value)) {
                    dap_json_rpc_error_add(l_jobj_errors, -1, "Bad value in OUT_COND_SUBTYPE_WALLET_SHARED");
                    log_it(L_ERROR, "Json TX: bad value in OUT_COND_SUBTYPE_WALLET_SHARED");
                    break;
                }
                
                int64_t l_min_sig_count;
                if(!s_json_get_int64_uint64(l_json_item_obj, "min_sig_count", &l_min_sig_count, false)) {
                    dap_json_rpc_error_add(l_jobj_errors, -1, "Bad min_sig_count in OUT_COND_SUBTYPE_WALLET_SHARED");
                    log_it(L_ERROR, "Json TX: bad min_sig_count in OUT_COND_SUBTYPE_WALLET_SHARED");
                    break;
                }
                
                // Read owner public key hashes array
                dap_json_t *l_json_pkey_hashes = dap_json_object_get_object(l_json_item_obj, "owner_pkey_hashes");
                if(!l_json_pkey_hashes || !dap_json_is_array(l_json_pkey_hashes)) {
                    dap_json_rpc_error_add(l_jobj_errors, -1, "Bad owner_pkey_hashes in OUT_COND_SUBTYPE_WALLET_SHARED");
                    log_it(L_ERROR, "Json TX: bad owner_pkey_hashes in OUT_COND_SUBTYPE_WALLET_SHARED");
                    break;
                }
                
                size_t l_pkey_hashes_count = dap_json_array_length(l_json_pkey_hashes);
                if(l_pkey_hashes_count == 0) {
                    dap_json_rpc_error_add(l_jobj_errors, -1, "Empty owner_pkey_hashes array in OUT_COND_SUBTYPE_WALLET_SHARED");
                    log_it(L_ERROR, "Json TX: empty owner_pkey_hashes array in OUT_COND_SUBTYPE_WALLET_SHARED");
                    break;
                }
                
                dap_hash_fast_t *l_pkey_hashes = DAP_NEW_Z_SIZE(dap_hash_fast_t, l_pkey_hashes_count * sizeof(dap_hash_fast_t));
                if(!l_pkey_hashes) {
                    dap_json_rpc_error_add(l_jobj_errors, -1, "Memory allocation error for pkey_hashes");
                    log_it(L_ERROR, "Json TX: memory allocation error for pkey_hashes");
                    break;
                }
                
                bool l_pkey_hashes_valid = true;
                for(size_t j = 0; j < l_pkey_hashes_count; j++) {
                    dap_json_t *l_json_hash = dap_json_array_get_idx(l_json_pkey_hashes, j);
                    if(!l_json_hash || !dap_json_is_string(l_json_hash)) {
                        dap_json_rpc_error_add(l_jobj_errors, -1, "Invalid pkey hash at index %zu", j);
                        log_it(L_ERROR, "Json TX: invalid pkey hash at index %zu", j);
                        l_pkey_hashes_valid = false;
                        break;
                    }
                    const char *l_hash_str = dap_json_get_string(l_json_hash);
                    if(dap_chain_hash_fast_from_str(l_hash_str, l_pkey_hashes + j)) {
                        dap_json_rpc_error_add(l_jobj_errors, -1, "Can't parse pkey hash '%s' at index %zu", l_hash_str, j);
                        log_it(L_ERROR, "Json TX: can't parse pkey hash '%s' at index %zu", l_hash_str, j);
                        l_pkey_hashes_valid = false;
                        break;
                    }
                }
                
                if(!l_pkey_hashes_valid) {
                    DAP_DELETE(l_pkey_hashes);
                    break;
                }
                
                // Read optional params
                const char *l_params_str = s_json_get_text(l_json_item_obj, "params");
                char *l_tag_str = NULL;
                if (l_params_str) {
                    size_t l_params_size = DAP_ENC_BASE58_DECODE_SIZE(dap_strlen(l_params_str));
                    l_tag_str = DAP_NEW_Z_SIZE(char, l_params_size + 1);
                    size_t l_decoded_size = dap_enc_base58_decode(l_params_str, l_tag_str);
                    if (l_decoded_size == 0) {
                        DAP_DEL_MULTY(l_pkey_hashes, l_tag_str);
                        dap_json_rpc_error_add(l_jobj_errors, -1, "Failed to decode params");
                        log_it(L_ERROR, "Json TX: failed to decode params in OUT_COND_SUBTYPE_WALLET_SHARED");
                        break;
                    }
                }
                
                uint64_t l_srv_uid;
                if(!s_json_get_srv_uid(l_json_item_obj, "service_id", "service", &l_srv_uid)) {
                    // Default service for wallet shared
                    l_srv_uid = DAP_CHAIN_WALLET_SHARED_ID;
                }
                
                dap_chain_tx_out_cond_t *l_out_cond_item = dap_chain_datum_tx_item_out_cond_create_wallet_shared(
                    (dap_chain_srv_uid_t){.uint64 = l_srv_uid}, l_value, (uint32_t)l_min_sig_count, l_pkey_hashes, l_pkey_hashes_count, l_tag_str);
                
                DAP_DEL_MULTY(l_pkey_hashes, l_tag_str);
                
                l_item = (uint8_t *) l_out_cond_item;
                if(l_item) {
                    SUM_256_256(l_value_need, l_value, &l_value_need);
                } else {
                    char *l_str_err = dap_strdup_printf("Unable to create conditional out for transaction "
                                                         "of type wallet_shared described in item %zu.", i);
                    dap_json_t *l_jobj_err = dap_json_object_new_string(l_str_err);
                    DAP_DELETE(l_str_err);
                    if (l_jobj_errors)
                        dap_json_array_add(l_jobj_errors, l_jobj_err);
                }
            } break;

            case DAP_CHAIN_TX_OUT_COND_SUBTYPE_UNDEFINED:
                log_it(L_WARNING, "Undefined subtype: '%s' of 'out_cond' item %zu ", l_subtype_str, i);
                char *l_str_err = dap_strdup_printf("Specified unknown sub type %s of conditional out on item %zu.",
                                                    l_subtype_str, i);
                dap_json_t *l_jobj_err = dap_json_object_new_string(l_str_err);
                DAP_DELETE(l_str_err);
                if (l_jobj_errors) dap_json_array_add(l_jobj_errors, l_jobj_err);
                break;
            }
        }
            break;
        case TX_ITEM_TYPE_SIG: {
            const char *l_sign_b64_str = dap_json_object_get_string(l_json_item_obj, "sig_b64");
            if (!l_sign_b64_str) {
                l_sign_list = dap_list_append(l_sign_list, l_json_item_obj);
                break;
            }
            int64_t l_sign_size = 0, l_sign_b64_strlen = strlen(l_sign_b64_str),
                    l_sign_decoded_size = DAP_ENC_BASE64_DECODE_SIZE(l_sign_b64_strlen);
            if ( !s_json_get_int64_uint64(l_json_item_obj, "sig_size", &l_sign_size, false) )
                log_it(L_NOTICE, "Json TX: \"sig_size\" unspecified, will be calculated automatically");

            dap_chain_tx_sig_t *l_tx_sig = DAP_NEW_Z_SIZE(dap_chain_tx_sig_t, sizeof(dap_chain_tx_sig_t) + l_sign_decoded_size);
            *l_tx_sig = (dap_chain_tx_sig_t) {
                .header = {
                    .type = TX_ITEM_TYPE_SIG, .version = 1,
                    .sig_size = dap_enc_base64_decode(l_sign_b64_str, l_sign_b64_strlen, l_tx_sig->sig, DAP_ENC_DATA_TYPE_B64_URLSAFE)
                }
            };

            debug_if(l_sign_size && l_tx_sig->header.sig_size != l_sign_size, L_ERROR,
                     "Json TX: sign size mismatch, %zu != %u!", l_sign_size, l_tx_sig->header.sig_size);
            /* But who cares?... */
            size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx), l_tx_items_size = l_tx->header.tx_items_size;
            l_tx->header.tx_items_size = 0;
            if ( dap_sign_verify_all((dap_sign_t*)l_tx_sig->sig, l_tx_sig->header.sig_size, (byte_t*)l_tx, l_tx_size) ) {
                dap_json_array_add(l_jobj_errors, dap_json_object_new_string("Sign verification failed!"));
                log_it(L_ERROR, "Json TX: sign verification failed!");
                break;
                // TODO: delete the datum and return
            } else {
                l_tx->header.tx_items_size = l_tx_items_size;
                l_item = (uint8_t *)l_tx_sig;
            }
        } break;
        case TX_ITEM_TYPE_RECEIPT: {
            uint64_t l_srv_uid = 0;
            if(!s_json_get_srv_uid(l_json_item_obj, "service_id", "service", &l_srv_uid)) {
                log_it(L_ERROR, "Json TX: bad service_id in TYPE_RECEIPT");
                break;
            }
            dap_chain_net_srv_price_unit_uid_t l_price_unit;
            if(!s_json_get_unit(l_json_item_obj, "price_unit", &l_price_unit)) {
                log_it(L_ERROR, "Json TX: bad price_unit in TYPE_RECEIPT");
                break;
            }
            int64_t l_units;
            if(!s_json_get_int64_uint64(l_json_item_obj, "units", &l_units, false)) {
                log_it(L_ERROR, "Json TX: bad units in TYPE_RECEIPT");
                break;
            }
            uint256_t l_value = { };
            if(!s_json_get_uint256(l_json_item_obj, "value", &l_value) || IS_ZERO_256(l_value)) {
                log_it(L_ERROR, "Json TX: bad value in TYPE_RECEIPT");
                break;
            }
            dap_hash_fast_t l_prev_tx_hash = {};
            const char* l_prev_tx_hash_str = NULL;
            if((l_prev_tx_hash_str = s_json_get_text(l_json_item_obj, "prev_tx")) == NULL) {
                log_it(L_ERROR, "Json TX: bad prev_tx in TYPE_RECEIPT");
                break;
            }
            dap_chain_hash_fast_from_str(l_prev_tx_hash_str, &l_prev_tx_hash);
            const char *l_params_str = s_json_get_text(l_json_item_obj, "params");
            size_t l_params_size = dap_strlen(l_params_str);
            dap_chain_datum_tx_receipt_t *l_receipt = dap_chain_datum_tx_receipt_create((dap_chain_srv_uid_t){.uint64 = l_srv_uid}, l_price_unit, l_units, l_value, l_params_str, l_params_size, &l_prev_tx_hash);
            l_item = (uint8_t *)l_receipt;
            if (!l_item) {
                char *l_str_err = dap_strdup_printf("Unable to create receipt out for transaction "
                                                    "described by item %zu.", i);
                dap_json_t *l_jobj_err = dap_json_object_new_string(l_str_err);
                DAP_DELETE(l_str_err);
                if (l_jobj_errors) dap_json_array_add(l_jobj_errors, l_jobj_err);
            }
        }
            break;
        case TX_ITEM_TYPE_TSD: {
            int64_t l_tsd_type;
            if(!s_json_get_int64_uint64(l_json_item_obj, "type_tsd", &l_tsd_type, false)) {
                log_it(L_ERROR, "Json TX: bad type_tsd in TYPE_TSD");
                break;
            }
            const char *l_tsd_data = s_json_get_text(l_json_item_obj, "data");
            if (!l_tsd_data) {
                log_it(L_ERROR, "Json TX: bad data in TYPE_TSD");
                break;
            }
            size_t l_data_size = dap_strlen(l_tsd_data);
            dap_chain_tx_tsd_t *l_tsd = dap_chain_datum_tx_item_tsd_create((void*)l_tsd_data, (int)l_tsd_type, l_data_size);
            l_item = (uint8_t *)l_tsd;
            // l_tsd_list = dap_list_append(l_tsd_list, l_tsd);
        }
            break;
            //case TX_ITEM_TYPE_PKEY:
                //break;
            //case TX_ITEM_TYPE_IN_EMS:
                //break;
            //case TX_ITEM_TYPE_IN_EMS_EXT:
                //break;
        }
        // Add item to transaction
        if(l_item) {
            dap_chain_datum_tx_add_item(&l_tx, (uint8_t *)l_item);
            l_items_ready++;
            DAP_DELETE(l_item);
        }
    }
    if (l_unstake){
        dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_back, l_value_delegated, l_native_token);
    }
    if (l_reward){
        dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_reward, l_value_reward, l_token_reward);
    }

    dap_list_t *l_list;
    // Add In items
    if(a_net){
        l_list = l_in_list;
        while(l_list) {
            dap_json_t *l_json_item_obj = (dap_json_t*) l_list->data;

            const char *l_json_item_addr_str = s_json_get_text(l_json_item_obj, "addr_from");
            const char *l_json_item_token = s_json_get_text(l_json_item_obj, "token");
            l_main_token = l_json_item_token;
            dap_chain_addr_t *l_addr_from = NULL;
            if(l_json_item_addr_str) {
                l_addr_from = dap_chain_addr_from_str(l_json_item_addr_str);
                if (!l_addr_from) {
                    log_it(L_WARNING, "Invalid element 'in', unable to convert string representation of addr_from: '%s' "
                                        "to binary.", l_json_item_addr_str);
                    char *l_str_err = dap_strdup_printf("Invalid element 'to', unable to convert string representation "
                                                        "of addr_from: '%s' to binary.", l_json_item_addr_str);
                    dap_json_t *l_jobj_err = dap_json_object_new_string(l_str_err);
                    DAP_DELETE(l_str_err);
                    if (l_jobj_errors) dap_json_array_add(l_jobj_errors, l_jobj_err);
                    // Go to the next item
                    l_list = dap_list_next(l_list);
                    continue;
                }
            }
            else {
                log_it(L_WARNING, "Invalid 'in' item, incorrect addr_from: '%s'", l_json_item_addr_str ? l_json_item_addr_str : "[null]");
                char *l_str_err = dap_strdup_printf("Invalid 'in' item, incorrect addr_from: '%s'",
                                            l_json_item_addr_str ? l_json_item_addr_str : "[null]");
                dap_json_t *l_jobj_err = dap_json_object_new_string(l_str_err);
                DAP_DELETE(l_str_err);
                if (l_jobj_errors) dap_json_array_add(l_jobj_errors, l_jobj_err);
                // Go to the next item
                l_list = dap_list_next(l_list);
                continue;
            }
            if(!l_json_item_token) {
                log_it(L_WARNING, "Invalid 'in' item, not found token name");
                dap_json_t *l_jobj_err = dap_json_object_new_string("Invalid 'in' item, not found token name");
                if (l_jobj_errors) dap_json_array_add(l_jobj_errors, l_jobj_err);
                // Go to the next item
                l_list = dap_list_next(l_list);
                continue;
            }
            if(IS_ZERO_256(l_value_need)) {
                log_it(L_WARNING, "Invalid 'in' item, not found value in out items");
                dap_json_t *l_jobj_err = dap_json_object_new_string("Invalid 'in' item, not found value in out items");
                if (l_jobj_errors) dap_json_array_add(l_jobj_errors, l_jobj_err);
                // Go to the next item
                l_list = dap_list_next(l_list);
                continue;
            }

            if(l_addr_from){
                // find the transactions from which to take away coins
                dap_list_t *l_list_used_out = NULL;
                dap_list_t *l_list_used_out_fee = NULL;
                uint256_t l_value_transfer = { }; // how many coins to transfer
                uint256_t l_value_transfer_fee = { }; // how many coins to transfer
                //SUM_256_256(a_value, a_value_fee, &l_value_need);
                uint256_t l_value_need_check = {};
                if (!dap_strcmp(l_native_token, l_main_token)) {
                    SUM_256_256(l_value_need_check, l_value_need, &l_value_need_check);
                    SUM_256_256(l_value_need_check, l_value_need_fee, &l_value_need_check);
                    l_list_used_out = dap_chain_wallet_get_list_tx_outs_with_val(a_net->pub.ledger, l_json_item_token,
                                                                                                l_addr_from, l_value_need_check, &l_value_transfer);
                    if(!l_list_used_out) {
                        log_it(L_WARNING, "Not enough funds in previous tx to transfer");
                        dap_json_t *l_jobj_err = dap_json_object_new_string("Can't create in transaction. Not enough funds in previous tx "
                                                            "to transfer");
                        if (l_jobj_errors) dap_json_array_add(l_jobj_errors, l_jobj_err);
                        // Go to the next item
                        l_list = dap_list_next(l_list);
                        continue;
                    }
                } else {
                    //CHECK value need
                    l_list_used_out = dap_chain_wallet_get_list_tx_outs_with_val(a_net->pub.ledger, l_json_item_token,
                                                                                                l_addr_from, l_value_need, &l_value_transfer);
                    if(!l_list_used_out) {
                        log_it(L_WARNING, "Not enough funds in previous tx to transfer");
                        dap_json_t *l_jobj_err = dap_json_object_new_string("Can't create in transaction. Not enough funds "
                                                                            "in previous tx to transfer");
                        if (l_jobj_errors) dap_json_array_add(l_jobj_errors, l_jobj_err);
                        // Go to the next item
                        l_list = dap_list_next(l_list);
                        continue;
                    }
                    //CHECK value fee
                    l_list_used_out_fee = dap_chain_wallet_get_list_tx_outs_with_val(a_net->pub.ledger, l_native_token,
                                                                                        l_addr_from, l_value_need_fee, &l_value_transfer_fee);
                    if(!l_list_used_out_fee && !l_unstake) {
                        log_it(L_WARNING, "Not enough funds in previous tx to transfer");
                        dap_json_t *l_jobj_err = dap_json_object_new_string("Can't create in transaction. Not enough funds "
                                                                            "in previous tx to transfer");
                        if (l_jobj_errors) dap_json_array_add(l_jobj_errors, l_jobj_err);
                        // Go to the next item
                        l_list = dap_list_next(l_list);
                        continue;
                    }
                }
                // add 'in' items
                uint256_t l_value_got = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
                assert(EQUAL_256(l_value_got, l_value_transfer));
                if (l_list_used_out_fee) {
                    uint256_t l_value_got_fee = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out_fee);
                    assert(EQUAL_256(l_value_got_fee, l_value_transfer_fee));
                    dap_list_free_full(l_list_used_out_fee, free);
                    // add 'out' item for coin fee back
                    uint256_t  l_value_back;
                    SUBTRACT_256_256(l_value_got_fee, l_value_need_fee, &l_value_back);
                    if (!IS_ZERO_256(l_value_back)) {
                        dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_from, l_value_back, l_native_token);
                        l_items_ready++;
                    }
                } else {
                    SUM_256_256(l_value_need, l_value_need_fee, &l_value_need);
                }
                dap_list_free_full(l_list_used_out, free);
                if(!IS_ZERO_256(l_value_got)) {
                    // add 'out' item for coin back
                    uint256_t l_value_back;
                    SUBTRACT_256_256(l_value_got, l_value_need, &l_value_back);
                    if(!IS_ZERO_256(l_value_back)) {
                        if (l_multichanel)
                            dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_from, l_value_back, l_main_token);
                        else
                            dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_from, l_value_back, l_native_token);
                        l_items_ready++;
                    }
                }
            }
            // Go to the next 'in' item
            l_list = dap_list_next(l_list);
        }
    }
    dap_list_free(l_in_list);

    // Add signs
    l_list = l_sign_list;
    while(l_list) {
        dap_json_t *l_json_item_obj = (dap_json_t*) l_list->data;
        dap_enc_key_t * l_enc_key  = NULL;

        //get wallet or cert
        dap_chain_wallet_t *l_wallet = s_json_get_wallet(l_json_item_obj, "wallet");
        const dap_cert_t *l_cert = s_json_get_cert(l_json_item_obj, "cert");

        int64_t l_pkey_size;
        int64_t l_sig_size;
        uint8_t *l_pkey = NULL;
        int64_t l_hash_type = 0;
        dap_sign_t *l_sign = NULL;


        //wallet goes first
        if (l_wallet) {
            l_enc_key = dap_chain_wallet_get_key(l_wallet, 0);
        } else if (l_cert && l_cert->enc_key) {
            l_enc_key = l_cert->enc_key;
        } else {
            dap_json_t *l_jobj_err = dap_json_object_new_string("Can't create sign for transactions.");
            dap_json_array_add(l_jobj_errors, l_jobj_err);
            log_it(L_ERROR, "Json TX: Item sign has no wallet or cert of they are invalid ");
            l_list = dap_list_next(l_list);
            continue;
        }

        if (l_sign) {
            size_t l_chain_sign_size = dap_sign_get_size(l_sign); // sign data

            dap_chain_tx_sig_t *l_tx_sig = DAP_NEW_Z_SIZE(dap_chain_tx_sig_t,
                    sizeof(dap_chain_tx_sig_t) + l_chain_sign_size);
            l_tx_sig->header.type = TX_ITEM_TYPE_SIG;
            l_tx_sig->header.sig_size =(uint32_t) l_chain_sign_size;
            memcpy(l_tx_sig->sig, l_sign, l_chain_sign_size);
            dap_chain_datum_tx_add_item(&l_tx, l_tx_sig);
            DAP_DELETE(l_sign);
        }

        if(l_enc_key && dap_chain_datum_tx_add_sign_item(&l_tx, l_enc_key) > 0) {
            l_items_ready++;
        } else {
            log_it(L_ERROR, "Json TX: Item sign has invalid enc_key.");
            l_list = dap_list_next(l_list);
            continue;
        }

        if (l_wallet) {
            dap_chain_wallet_close(l_wallet);
            dap_enc_key_delete(l_enc_key);
        }
        l_list = dap_list_next(l_list);
    }

    dap_list_free(l_sign_list);
    dap_json_object_free(l_json);

    *a_out_tx = l_tx;

    if(a_items_count)
        *a_items_count = l_items_count;

    if(a_items_ready)
        *a_items_ready = l_items_ready;

    return DAP_CHAIN_NET_TX_CREATE_JSON_OK;
}


int dap_chain_tx_datum_from_json(dap_json_t *a_tx_json, dap_chain_net_t *a_net, dap_json_t *a_jobj_arr_errors, 
    dap_chain_datum_tx_t** a_out_tx, size_t* a_items_count, size_t *a_items_ready)
{

    int l_type_tx = 0;
    if (!a_tx_json) {
        dap_json_rpc_error_add(a_jobj_arr_errors,DAP_CHAIN_NET_TX_CREATE_JSON_CAN_NOT_OPEN_JSON_FILE,"Empty json");
        return log_it(L_ERROR, "Empty json"), DAP_CHAIN_NET_TX_CREATE_JSON_CAN_NOT_OPEN_JSON_FILE;
    }

    if(!a_out_tx){
        dap_json_rpc_error_add(a_jobj_arr_errors,DAP_CHAIN_NET_TX_CREATE_JSON_WRONG_ARGUMENTS,"a_out_tx is NULL");
        log_it(L_ERROR, "a_out_tx is NULL");
        return DAP_CHAIN_NET_TX_CREATE_JSON_WRONG_ARGUMENTS;
    }

    // Read items and net from json file
    dap_json_t *l_json_items = NULL;
    dap_json_object_get_ex(a_tx_json, "items", &l_json_items);
    size_t l_items_count;
    if(!l_json_items || !dap_json_is_array(l_json_items) || !(l_items_count = dap_json_array_length(l_json_items))) {
        return DAP_CHAIN_NET_TX_CREATE_JSON_NOT_FOUNT_ARRAY_ITEMS;
    } 
    const char *l_net_str = dap_json_object_get_string(a_tx_json, "net"); 
    dap_chain_net_t * l_net = dap_chain_net_by_name(l_net_str);
    if (l_net_str && !l_net && !a_net) {
        dap_json_rpc_error_add(a_jobj_arr_errors,DAP_CHAIN_NET_TX_CREATE_JSON_NOT_FOUNT_NET_IN_JSON,"not found net by name '%s'", l_net_str);
        log_it(L_ERROR, "not found net by name '%s'", l_net_str);
        return DAP_CHAIN_NET_TX_CREATE_JSON_NOT_FOUNT_NET_IN_JSON;
    }
    l_net = l_net ? l_net : a_net;
    log_it(L_NOTICE, "Json TX: found %lu items", l_items_count);

    // Create transaction
    dap_chain_datum_tx_t *l_tx = DAP_NEW_Z_SIZE(dap_chain_datum_tx_t, sizeof(dap_chain_datum_tx_t));
    if(!l_tx) {
        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
    }

    int64_t l_ts_created = dap_json_object_get_int64(a_tx_json, "ts_created");
    l_tx->header.ts_created = l_ts_created ? l_ts_created : time(NULL);

    size_t l_items_ready = 0;
    dap_list_t *l_sign_list = NULL;// list 'sign' items

    uint256_t l_value_need = { };// how many tokens are needed in the 'out' item

    dap_chain_addr_t l_seller_addr = {};

    if(l_net){ // if composition is not offline
        l_type_tx = s_dap_chain_net_tx_json_check(l_items_count, l_json_items, a_jobj_arr_errors, l_net);
    }
    if (l_type_tx == DAP_CHAIN_NET_TX_TYPE_ERR){
        return DAP_CHAIN_NET_TX_CREATE_JSON_TRANSACTION_NOT_CORRECT_ERR;
    }
    if (l_type_tx == DAP_CHAIN_NET_TX_STAKE_UNLOCK)
        l_items_ready++;
        
    // Creating and adding items to the transaction
    for(size_t i = 0; i < l_items_count; ++i) {
        dap_json_t *l_json_item_obj = dap_json_array_get_idx(l_json_items, i);
        if(!l_json_item_obj || !dap_json_is_object(l_json_item_obj)) {
            continue;
        }
        const char *l_item_type_str = dap_json_object_get_string(l_json_item_obj, "type");
        if(!l_item_type_str) {
            log_it(L_WARNING, "Item %zu without type", i);
            continue;
        }
        dap_chain_tx_item_type_t l_item_type = dap_chain_datum_tx_item_type_from_str_short(l_item_type_str);
        if(l_item_type == TX_ITEM_TYPE_UNKNOWN) {
            log_it(L_WARNING, "Item %zu has invalid type '%s'", i, l_item_type_str);
            continue;
        }

        log_it(L_DEBUG, "Json TX: process item %s", l_item_type_str);
        // Create an item depending on its type
        uint8_t *l_item = NULL;
        switch (l_item_type) {
            case TX_ITEM_TYPE_IN: {                
                l_item = s_dap_chain_net_tx_create_in_item(l_json_item_obj, a_jobj_arr_errors);
            }break;
            case TX_ITEM_TYPE_IN_COND: {
                l_item = s_dap_chain_net_tx_create_in_cond_item(l_json_item_obj, a_jobj_arr_errors, l_net);            
            }break;
            case TX_ITEM_TYPE_IN_EMS: {
                l_item = s_dap_chain_net_tx_create_in_ems_item(l_json_item_obj, a_jobj_arr_errors);           
            }break;
            case TX_ITEM_TYPE_IN_REWARD: {
                l_item = s_dap_chain_net_tx_create_in_reward_item(l_json_item_obj, a_jobj_arr_errors);
            }break;
            case TX_ITEM_TYPE_OUT_EXT: {
                l_item = s_dap_chain_net_tx_create_out_ext_item(l_json_item_obj, a_jobj_arr_errors,l_type_tx);
            }break;
            case TX_ITEM_TYPE_OUT_STD: {
                l_item = s_dap_chain_net_tx_create_out_std_item(l_json_item_obj, a_jobj_arr_errors,l_type_tx);
            }break;
            case TX_ITEM_TYPE_OUT_COND: {
                l_item = s_dap_chain_net_tx_create_out_cond_item(l_json_item_obj, a_jobj_arr_errors, l_type_tx, &l_value_need, &l_seller_addr, i, l_net);
            }break;
            case TX_ITEM_TYPE_SIG: {
                l_item = s_dap_chain_net_tx_create_sig_item(l_json_item_obj, a_jobj_arr_errors, l_tx, &l_sign_list);
                if(l_sign_list)continue;       
            }break;
            case TX_ITEM_TYPE_RECEIPT: {
                l_item = s_dap_chain_net_tx_create_receipt_item(l_json_item_obj, a_jobj_arr_errors, l_tx, l_sign_list, i);
            }break;
            case TX_ITEM_TYPE_TSD: {
                l_item = s_dap_chain_net_tx_create_tsd_item(l_json_item_obj, a_jobj_arr_errors, l_tx, l_sign_list);
            }break;
            case TX_ITEM_TYPE_VOTING: {
                l_item = s_dap_chain_net_tx_create_voting_item(a_jobj_arr_errors);
            }break;
            case TX_ITEM_TYPE_VOTE: {
                l_item = s_dap_chain_net_tx_create_vote_item(l_json_item_obj, a_jobj_arr_errors);
            }break;
        }
        if (!l_item) {
            log_it(L_ERROR, "Item %zu can't created, exit from creator!", i);
            dap_json_rpc_error_add(a_jobj_arr_errors,DAP_CHAIN_NET_TX_CREATE_JSON_CANT_CREATED_ITEM_ERR,"Item %zu can't created, exit from creator!", i);
            DAP_DELETE(l_tx);
            return DAP_CHAIN_NET_TX_CREATE_JSON_CANT_CREATED_ITEM_ERR;
        } else {        
            // Add item to transaction
            dap_chain_datum_tx_add_item(&l_tx, (uint8_t *)l_item);
            l_items_ready++;
            DAP_DELETE(l_item);
        }

    }

    dap_list_t *l_list;
    // Add signs
    l_list = l_sign_list;

    while(l_list) {
        dap_json_t *l_json_item_obj = (dap_json_t*) l_list->data;
        dap_enc_key_t * l_enc_key  = NULL;
        
        //get wallet or cert
        dap_chain_wallet_t *l_wallet = s_json_get_wallet(l_json_item_obj, "wallet");
        const dap_cert_t *l_cert = s_json_get_cert(l_json_item_obj, "cert");

        dap_sign_t *l_sign = NULL;        

        //wallet goes first
        if (l_wallet) {
            l_enc_key = dap_chain_wallet_get_key(l_wallet, 0);
        } else if (l_cert && l_cert->enc_key) {
            l_enc_key = l_cert->enc_key; 
        } else {
            if (a_jobj_arr_errors)
                dap_json_rpc_error_add(a_jobj_arr_errors,-1,"Json TX: Item sign has no wallet or cert of they are invalid ");
            log_it(L_ERROR, "Json TX: Item sign has no wallet or cert of they are invalid ");
            l_list = dap_list_next(l_list);
            continue;
        }

        if (l_sign) { // WTF is this for?... 
            size_t l_chain_sign_size = dap_sign_get_size(l_sign); // sign data
            
            dap_chain_tx_sig_t *l_tx_sig = DAP_NEW_Z_SIZE(dap_chain_tx_sig_t,
                    sizeof(dap_chain_tx_sig_t) + l_chain_sign_size);
            l_tx_sig->header.type = TX_ITEM_TYPE_SIG;
            l_tx_sig->header.sig_size =(uint32_t) l_chain_sign_size;
            memcpy(l_tx_sig->sig, l_sign, l_chain_sign_size);
            dap_chain_datum_tx_add_item(&l_tx, l_tx_sig);
            DAP_DELETE(l_sign);
        }

        if(l_enc_key && dap_chain_datum_tx_add_sign_item(&l_tx, l_enc_key) > 0) {
            l_items_ready++;
        } else {
            log_it(L_ERROR, "Json TX: Item sign has invalid enc_key.");
            l_list = dap_list_next(l_list);
            continue;
        }

        if (l_wallet) {
            dap_chain_wallet_close(l_wallet);  
            dap_enc_key_delete(l_enc_key);
        }  
        l_list = dap_list_next(l_list);
    }

    dap_list_free(l_sign_list);

    if (dap_chain_datum_tx_verify_sign_all(l_tx)) {
        log_it(L_ERROR, "Json TX: Sign verification failed!");
        if (a_jobj_arr_errors)
            dap_json_rpc_error_add(a_jobj_arr_errors,-1,"Sign verification failed!");
        DAP_DELETE(l_tx);
        return DAP_CHAIN_NET_TX_CREATE_JSON_SIGN_VERIFICATION_FAILED;
    }

    *a_out_tx = l_tx;

    if(a_items_count)
        *a_items_count = l_items_count;

    if(a_items_ready)
        *a_items_ready = l_items_ready;

    return DAP_CHAIN_NET_TX_CREATE_JSON_OK;   

}


int dap_chain_net_tx_to_json(dap_chain_datum_tx_t *a_tx, dap_json_t *a_out_json)
{
    if(!a_tx || !a_out_json)
        return log_it(L_ERROR, "Empty transaction"), DAP_CHAIN_NET_TX_CREATE_JSON_WRONG_ARGUMENTS;

    // Create a new json_object and assign it to the dap_json_t pointer
    dap_json_t* json_obj_out = dap_json_object_new();
    if (!json_obj_out)
        return log_it(L_ERROR, "Failed to allocate JSON object"), -1;
    
    dap_json_t* json_arr_items = dap_json_array_new();
    if (!json_arr_items) {
        dap_json_object_free(json_obj_out);
        return log_it(L_ERROR, "Failed to allocate JSON array"), -1;
    }
    
    dap_json_t* l_json_arr_reply = NULL;
    dap_hash_fast_t l_hash_tmp = { };
    byte_t *item; size_t l_size;
    char *l_hash_str = NULL;
    char l_tmp_buf[DAP_TIME_STR_SIZE];

    char *l_tx_hash_str = dap_hash_fast_str_new(a_tx, dap_chain_datum_tx_get_size(a_tx));

    dap_json_object_add_string(json_obj_out, "datum_hash", l_tx_hash_str);
    
    dap_json_t *l_ts_obj = dap_json_object_new_int64(a_tx->header.ts_created);
    if (l_ts_obj)
        dap_json_object_add_object(json_obj_out, "ts_created", l_ts_obj);
    
    dap_json_object_add_string(json_obj_out, "datum_type", "tx");

    TX_ITEM_ITER_TX(item, l_size, a_tx) {
        dap_json_t* json_obj_item = dap_json_object_new();
        if (!json_obj_item) {
            log_it(L_WARNING, "Failed to allocate JSON object for TX item");
            continue;
        }
        
        dap_json_t *l_type_obj = dap_json_object_new_string(dap_chain_datum_tx_item_type_to_str_short(*item));
        if (l_type_obj)
            dap_json_object_add_object(json_obj_item,"type", l_type_obj);
        switch (*item) {
        case TX_ITEM_TYPE_IN:
            l_hash_tmp = ((dap_chain_tx_in_t*)item)->header.tx_prev_hash;
            l_hash_str = dap_hash_fast_to_str_static(&l_hash_tmp);
            dap_json_object_add_object(json_obj_item,"prev_hash", dap_json_object_new_string(l_hash_str));
            dap_json_object_add_object(json_obj_item,"out_prev_idx", dap_json_object_new_uint64(((dap_chain_tx_in_t*)item)->header.tx_out_prev_idx));
            break;
        case TX_ITEM_TYPE_OUT: {
            const char *l_coins_str, *l_value_str = dap_uint256_to_char( ((dap_chain_tx_out_t*)item)->header.value, &l_coins_str );
            dap_json_object_add_object(json_obj_item,"addr", dap_json_object_new_string(dap_chain_addr_to_str_static(&((dap_chain_tx_out_t*)item)->addr)));
            dap_json_object_add_object(json_obj_item,"value", dap_json_object_new_string(l_value_str));
        } break;
        case TX_ITEM_TYPE_SIG: {
            dap_sign_t *l_sign = dap_chain_datum_tx_item_sig_get_sign((dap_chain_tx_sig_t*)item);
            char *l_sign_b64 = DAP_NEW_Z_SIZE(char, DAP_ENC_BASE64_ENCODE_SIZE(dap_sign_get_size(l_sign)) + 1);
            size_t l_sign_size = dap_sign_get_size(l_sign);
            dap_enc_base64_encode(l_sign, l_sign_size, l_sign_b64, DAP_ENC_DATA_TYPE_B64_URLSAFE);
            dap_json_object_add_object(json_obj_item, "sig_size",   dap_json_object_new_uint64(l_sign_size));
            dap_json_object_add_object(json_obj_item, "sig_b64",    dap_json_object_new_string(l_sign_b64));
            dap_json_object_add_object(json_obj_item, "sig_version", dap_json_object_new_int(((dap_chain_tx_sig_t*)item)->header.version));
            DAP_DELETE(l_sign_b64);

        } break;
        case TX_ITEM_TYPE_TSD: {
            dap_tsd_t *l_tsd = (dap_tsd_t *)((dap_chain_tx_tsd_t*)item)->tsd;
            dap_json_object_add_object(json_obj_item,"data_type", dap_json_object_new_int(l_tsd->type));
            dap_json_object_add_object(json_obj_item,"data_size", dap_json_object_new_uint64(l_tsd->size));
            char *l_tsd_str = dap_enc_base58_encode_to_str(l_tsd->data, l_tsd->size);
            dap_json_object_add_object(json_obj_item,"data", dap_json_object_new_string(l_tsd_str));
            DAP_DELETE(l_tsd_str);
        } break;
        case TX_ITEM_TYPE_IN_COND:
            l_hash_tmp = ((dap_chain_tx_in_cond_t*)item)->header.tx_prev_hash;
            l_hash_str = dap_hash_fast_to_str_static(&l_hash_tmp);
            dap_json_object_add_object(json_obj_item,"receipt_idx", dap_json_object_new_int(((dap_chain_tx_in_cond_t*)item)->header.receipt_idx));
            dap_json_object_add_object(json_obj_item,"prev_hash", dap_json_object_new_string(l_hash_str));
            dap_json_object_add_object(json_obj_item,"out_prev_idx", dap_json_object_new_uint64(((dap_chain_tx_in_cond_t*)item)->header.tx_out_prev_idx));
            break;
        case TX_ITEM_TYPE_OUT_COND: {
            char l_tmp_buff[70]={0};
            const char *l_coins_str, *l_value_str = dap_uint256_to_char(((dap_chain_tx_out_cond_t*)item)->header.value, &l_coins_str);
            dap_time_t l_ts_exp = ((dap_chain_tx_out_cond_t*)item)->header.ts_expires;
            if (l_ts_exp > 0)
                dap_time_to_str_rfc822(l_tmp_buf, DAP_TIME_STR_SIZE, l_ts_exp);
            dap_json_object_add_object(json_obj_item,"ts_expires", l_ts_exp ? dap_json_object_new_string(l_tmp_buf) : dap_json_object_new_string("never"));
            dap_json_object_add_object(json_obj_item,"value", dap_json_object_new_string(l_value_str));
            dap_json_object_add_string(json_obj_item, "coins", l_coins_str);
            sprintf(l_tmp_buff,"0x%016"DAP_UINT64_FORMAT_x"",((dap_chain_tx_out_cond_t*)item)->header.srv_uid.uint64);
            dap_json_object_add_object(json_obj_item,"service_id", dap_json_object_new_string(l_tmp_buff));
            dap_json_object_add_object(json_obj_item,"subtype", dap_json_object_new_string(dap_chain_tx_out_cond_subtype_to_str_short(((dap_chain_tx_out_cond_t*)item)->header.subtype)));
            switch (((dap_chain_tx_out_cond_t*)item)->header.subtype) {
                case DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE:
                    break;
                case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY: {
                    const char *l_coins_str, *l_value_str =
                        dap_uint256_to_char( ((dap_chain_tx_out_cond_t*)item)->subtype.srv_pay.unit_price_max_datoshi, &l_coins_str );
                    l_hash_tmp = ((dap_chain_tx_out_cond_t*)item)->subtype.srv_pay.pkey_hash;
                    l_hash_str = dap_hash_fast_to_str_static(&l_hash_tmp);
                    const char *l_unit = dap_chain_net_srv_price_unit_uid_to_str(((dap_chain_tx_out_cond_t*)item)->subtype.srv_pay.unit);
                    dap_json_object_add_object(json_obj_item,"price_unit", dap_json_object_new_string(l_unit));
                    dap_json_object_add_object(json_obj_item,"pkey_hash", dap_json_object_new_string(l_hash_str));
                    dap_json_object_add_object(json_obj_item,"value_max_per_unit", dap_json_object_new_string(l_value_str));
                } break;
                case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE: {
                    dap_chain_node_addr_t *l_signer_node_addr = &((dap_chain_tx_out_cond_t*)item)->subtype.srv_stake_pos_delegate.signer_node_addr;
                    dap_chain_addr_t *l_signing_addr = &((dap_chain_tx_out_cond_t*)item)->subtype.srv_stake_pos_delegate.signing_addr;
                    l_hash_tmp = l_signing_addr->data.hash_fast;
                    l_hash_str = dap_hash_fast_to_str_static(&l_hash_tmp);
                    dap_json_object_add_object(json_obj_item,"signing_addr", dap_json_object_new_string(dap_chain_addr_to_str_static(l_signing_addr)));
                    sprintf(l_tmp_buff,""NODE_ADDR_FP_STR"",NODE_ADDR_FP_ARGS(l_signer_node_addr));
                    dap_json_object_add_object(json_obj_item,"signer_node_addr", dap_json_object_new_string(l_tmp_buff));
                    dap_json_object_add_object(json_obj_item,"subtype", dap_json_object_new_string("srv_stake_pos_delegate"));
                } break;
                case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE: {
                    const char
                        *l_rate_str,
                        *l_tmp_str = dap_uint256_to_char( (((dap_chain_tx_out_cond_t*)item)->subtype.srv_xchange.rate), &l_rate_str );
                    sprintf(l_tmp_buff,"0x%016"DAP_UINT64_FORMAT_x"",((dap_chain_tx_out_cond_t*)item)->subtype.srv_xchange.buy_net_id.uint64);
                    dap_json_object_add_object(json_obj_item,"buy_net_id", dap_json_object_new_string(l_tmp_buff));
                    sprintf(l_tmp_buff,"0x%016"DAP_UINT64_FORMAT_x"",((dap_chain_tx_out_cond_t*)item)->subtype.srv_xchange.sell_net_id.uint64);
                    dap_json_object_add_object(json_obj_item,"sell_net_id", dap_json_object_new_string(l_tmp_buff));
                    dap_json_object_add_object(json_obj_item,"buy_token", dap_json_object_new_string(((dap_chain_tx_out_cond_t*)item)->subtype.srv_xchange.buy_token));
                    dap_json_object_add_object(json_obj_item,"seller_addr", dap_json_object_new_string(dap_chain_addr_to_str_static( &((dap_chain_tx_out_cond_t*)item)->subtype.srv_xchange.seller_addr ))); 
                    dap_json_object_add_object(json_obj_item,"rate", dap_json_object_new_string(l_rate_str));
                } break;
                case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK: {
                    dap_time_t l_ts_unlock = ((dap_chain_tx_out_cond_t*)item)->subtype.srv_stake_lock.time_unlock;
                    snprintf(l_tmp_buf, DAP_TIME_STR_SIZE, "%"DAP_UINT64_FORMAT_U, l_ts_unlock);
                    dap_json_object_add_object(json_obj_item,"time_staking", dap_json_object_new_string(l_tmp_buf));
                    char *l_reinvest_percent = dap_chain_balance_coins_print(((dap_chain_tx_out_cond_t*)item)->subtype.srv_stake_lock.reinvest_percent);
                    dap_json_object_add_string(json_obj_item, "reinvest_percent", l_reinvest_percent);
                    DAP_DELETE(l_reinvest_percent);
                } break;
                default: break;
            }
            if (((dap_chain_tx_out_cond_t*)item)->tsd_size) {
                char *l_params_str = dap_enc_base58_encode_to_str(((dap_chain_tx_out_cond_t*)item)->tsd, ((dap_chain_tx_out_cond_t*)item)->tsd_size);
                dap_json_object_add_object(json_obj_item,"params", dap_json_object_new_string(l_params_str));
                DAP_DELETE(l_params_str);
            }
        } break;
        case TX_ITEM_TYPE_IN_EMS: {
            dap_json_object_add_object(json_obj_item,"chain_id", dap_json_object_new_uint64(((dap_chain_tx_in_ems_t*)item)->header.token_emission_chain_id.uint64));
            dap_json_object_add_object(json_obj_item,"token", dap_json_object_new_string(((dap_chain_tx_in_ems_t*)item)->header.ticker));
            dap_json_object_add_object(json_obj_item,"token_ems_hash", dap_json_object_new_string( dap_hash_fast_to_str_static(&((dap_chain_tx_in_ems_t*)item)->header.token_emission_hash)));
            
        } break;

        case TX_ITEM_TYPE_OUT_EXT: {
            const char *l_coins_str, *l_value_str = dap_uint256_to_char( ((dap_chain_tx_out_ext_t*)item)->header.value, &l_coins_str );
            dap_json_object_add_object(json_obj_item,"addr", dap_json_object_new_string(dap_chain_addr_to_str_static(&((dap_chain_tx_out_ext_t*)item)->addr)));
            dap_json_object_add_object(json_obj_item,"token", dap_json_object_new_string(((dap_chain_tx_out_ext_t*)item)->token));
            dap_json_object_add_object(json_obj_item,"value", dap_json_object_new_string(l_value_str));
            dap_json_object_add_string(json_obj_item, "coins", l_coins_str);

        } break;

        case TX_ITEM_TYPE_OUT_STD: {
            const char *l_coins_str, *l_value_str = dap_uint256_to_char( ((dap_chain_tx_out_std_t *)item)->value, &l_coins_str );
            dap_json_object_add_string(json_obj_item, "type", "out_std");
            dap_json_object_add_object(json_obj_item, "addr", dap_json_object_new_string(dap_chain_addr_to_str_static(&((dap_chain_tx_out_std_t *)item)->addr)));
            dap_json_object_add_object(json_obj_item, "token", dap_json_object_new_string(((dap_chain_tx_out_std_t *)item)->token));
            dap_json_object_add_string(json_obj_item, "value", l_value_str);
            dap_json_object_add_string(json_obj_item, "coins", l_coins_str);
            dap_time_t l_ts_unlock = ((dap_chain_tx_out_std_t *)item)->ts_unlock;
            snprintf(l_tmp_buf, DAP_TIME_STR_SIZE, "%"DAP_UINT64_FORMAT_U, l_ts_unlock);
            dap_json_object_add_string(json_obj_item, "time_unlock", l_tmp_buf);
        } break;

        case TX_ITEM_TYPE_VOTING:{
            size_t l_tsd_size = 0;
            dap_chain_tx_tsd_t *l_item = (dap_chain_tx_tsd_t *)dap_chain_datum_tx_item_get(a_tx, NULL, (byte_t*)item + l_size, TX_ITEM_TYPE_TSD, &l_tsd_size);
            if (!l_item || !l_tsd_size)
                    break;
            dap_chain_datum_tx_voting_params_t *l_voting_params = dap_chain_datum_tx_voting_parse_tsd(a_tx);
            dap_json_object_add_object(json_obj_item,"type", dap_json_object_new_string("voting"));
            dap_json_object_add_object(json_obj_item,"voting_question", dap_json_object_new_string(l_voting_params->question));
            dap_json_t *l_json_array = dap_json_array_new();
            dap_json_object_add_string(json_obj_item, "token", l_voting_params->token_ticker);
            dap_list_t *l_temp = l_voting_params->options;
            uint8_t l_index = 0;
            while (l_temp) {
                dap_json_array_add(l_json_array, dap_json_object_new_string((char *)l_temp->data));
                l_index++;
                l_temp = l_temp->next;
            }
            dap_json_object_add_object(json_obj_item, "answer_options", l_json_array);
            if (l_voting_params->voting_expire) {
                snprintf(l_tmp_buf, DAP_TIME_STR_SIZE, "%"DAP_UINT64_FORMAT_U, l_voting_params->voting_expire);
                dap_json_object_add_string(json_obj_item, "voting_expire", l_tmp_buf);
            }
            if (l_voting_params->votes_max_count) {
                dap_json_object_add_uint64(json_obj_item, "votes_max_count", l_voting_params->votes_max_count);
            }
            dap_json_object_add_object(json_obj_item,"changing_vote", dap_json_object_new_bool(l_voting_params->vote_changing_allowed));
            dap_json_object_add_object(json_obj_item,"delegate_key_required", dap_json_object_new_bool(l_voting_params->delegate_key_required));  
            dap_list_free_full(l_voting_params->options, NULL);
            DAP_DELETE(l_voting_params->question);
            DAP_DELETE(l_voting_params);
        } break;
        case TX_ITEM_TYPE_VOTE:{
            dap_chain_tx_vote_t *l_vote_item = (dap_chain_tx_vote_t *)item;
            const char *l_hash_str = dap_chain_hash_fast_to_str_static(&l_vote_item->voting_hash);
            dap_json_object_add_object(json_obj_item,"type", dap_json_object_new_string("vote"));
            dap_json_object_add_object(json_obj_item,"voting_hash", dap_json_object_new_string(l_hash_str));
            dap_json_object_add_object(json_obj_item,"answer_idx", dap_json_object_new_uint64(l_vote_item->answer_idx));
        } break;
        case TX_ITEM_TYPE_IN_REWARD:{
            const char *l_hash_str = dap_chain_hash_fast_to_str_static(&((dap_chain_tx_in_reward_t *)item)->block_hash);
            dap_json_object_add_object(json_obj_item,"block_hash", dap_json_object_new_string(l_hash_str));
        } break;
        default:
            dap_json_object_add_object(json_obj_item,"type", dap_json_object_new_string("This transaction have unknown item type"));
            break;
        }
        dap_json_array_add(json_arr_items, json_obj_item);
    }

    dap_json_object_add_object(json_obj_out, "items", json_arr_items);

    if(a_out_json) {
        // Cast json_object to dap_json_t for assignment
        *(dap_json_t **)a_out_json = (dap_json_t *)json_obj_out;
    }

    return 0;
}
