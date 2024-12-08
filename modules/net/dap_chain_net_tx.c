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
#include "dap_chain_ledger.h"
#include "dap_chain_datum_tx_in_cond.h"
#include "dap_chain_tx.h"
#include "dap_list.h"

#define LOG_TAG "dap_chain_net_tx"

typedef struct cond_all_with_spends_by_srv_uid_arg{
    dap_chain_datum_tx_spends_items_t * ret;
    dap_chain_net_srv_uid_t srv_uid;
    dap_time_t time_from;
    dap_time_t time_to;
} cond_all_with_spends_by_srv_uid_arg_t;

typedef struct cond_all_by_srv_uid_arg{
    dap_list_t * ret;
    dap_chain_net_srv_uid_t srv_uid;
    dap_time_t time_from;
    dap_time_t time_to;
} cond_all_by_srv_uid_arg_t;

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
dap_chain_datum_tx_spends_items_t * dap_chain_net_get_tx_cond_all_with_spends_by_srv_uid(dap_chain_net_t * a_net, const dap_chain_net_srv_uid_t a_srv_uid,
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
    dap_chain_net_srv_uid_t srv_uid;
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
dap_list_t * dap_chain_net_get_tx_cond_chain(dap_chain_net_t * a_net, dap_hash_fast_t * a_tx_hash, dap_chain_net_srv_uid_t a_srv_uid)
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
    dap_chain_net_srv_uid_t srv_uid;
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
dap_list_t * dap_chain_net_get_tx_cond_all_for_addr(dap_chain_net_t * a_net, dap_chain_addr_t * a_addr, dap_chain_net_srv_uid_t a_srv_uid)
{
    struct get_tx_cond_all_for_addr * l_args = DAP_NEW_Z(struct get_tx_cond_all_for_addr);
    if (!l_args) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    l_args->addr = a_addr;
    l_args->srv_uid = a_srv_uid;
    dap_chain_net_get_tx_all(a_net,TX_SEARCH_TYPE_NET, s_get_tx_cond_all_for_addr_callback, l_args);
    dap_chain_tx_hh_free(l_args->tx_all_hh);
    dap_list_t * l_ret = l_args->ret;
    DAP_DELETE(l_args);
    return l_ret;
}

static void s_tx_cond_all_by_srv_uid_callback(UNUSED_ARG dap_chain_net_t* a_net, dap_chain_datum_tx_t *a_tx, UNUSED_ARG dap_hash_fast_t *a_tx_hash, void *a_arg)
{
    cond_all_by_srv_uid_arg_t *l_ret = (cond_all_by_srv_uid_arg_t*)a_arg;

    if (( l_ret->time_from && a_tx->header.ts_created < l_ret->time_from )
        || ( l_ret->time_to && a_tx->header.ts_created > l_ret->time_to ))
        return;

    byte_t *item; size_t l_size;
    dap_chain_datum_tx_cond_list_item_t *l_item = (dap_chain_datum_tx_cond_list_item_t*) DAP_NEW_Z(dap_chain_datum_tx_cond_list_item_t);
    TX_ITEM_ITER_TX(item, l_size, a_tx) {
        if ( *item == TX_ITEM_TYPE_OUT_COND && l_ret->srv_uid.uint64 == ((dap_chain_tx_out_cond_t*)item)->header.srv_uid.uint64 ){
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
dap_list_t * dap_chain_net_get_tx_cond_all_by_srv_uid(dap_chain_net_t * a_net, const dap_chain_net_srv_uid_t a_srv_uid,
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
