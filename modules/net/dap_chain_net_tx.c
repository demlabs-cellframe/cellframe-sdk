/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Cellframe Network https://cellframe.net
 * Copyright  (c) 2022
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

#include <string.h>
#include "dap_chain_net_tx.h"
#include "dap_chain_cell.h"
#include "dap_chain_common.h"
#include "dap_chain_datum_tx_in_cond.h"
#include "dap_chain_tx.h"
#include "dap_list.h"

#define LOG_TAG "dap_chain_net_tx"

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
    dap_ledger_t * l_ledger = a_net->pub.ledger;
    dap_chain_datum_tx_spends_items_t * l_ret = DAP_NEW_Z(dap_chain_datum_tx_spends_items_t);
    if (!l_ret) {
        log_it(L_ERROR, "Memory allocation error in dap_chain_net_get_tx_cond_all_with_spends_by_srv_uid");
        return NULL;
    }

    switch (a_search_type) {
        case TX_SEARCH_TYPE_NET:
        case TX_SEARCH_TYPE_CELL:
        case TX_SEARCH_TYPE_LOCAL:
        case TX_SEARCH_TYPE_CELL_SPENT:
        case TX_SEARCH_TYPE_NET_UNSPENT:
        case TX_SEARCH_TYPE_CELL_UNSPENT:
        case TX_SEARCH_TYPE_NET_SPENT: {
            // pass all chains
            for ( dap_chain_t * l_chain = a_net->pub.chains; l_chain; l_chain = l_chain->next){
                dap_chain_cell_t * l_cell, *l_cell_tmp;
                // Go through all cells
                HASH_ITER(hh,l_chain->cells,l_cell, l_cell_tmp){
                    dap_chain_atom_iter_t * l_atom_iter = l_chain->callback_atom_iter_create(l_chain,l_cell->id, false  );
                    // try to find transaction in chain ( inside shard )
                    size_t l_atom_size = 0;
                    dap_chain_atom_ptr_t l_atom = l_chain->callback_atom_iter_get_first(l_atom_iter, &l_atom_size);

                    // Check atoms in chain
                    while(l_atom && l_atom_size) {
                        size_t l_datums_count = 0;
                        dap_chain_datum_t **l_datums = l_chain->callback_atom_get_datums(l_atom, l_atom_size, &l_datums_count);
                        // transaction
                        dap_chain_datum_tx_t *l_tx = NULL;

                        for (size_t i = 0; i < l_datums_count; i++) {
                            // Check if its transaction
                            if (l_datums && (l_datums[i]->header.type_id == DAP_CHAIN_DATUM_TX)) {
                                l_tx = (dap_chain_datum_tx_t *)l_datums[i]->data;
                            }

                            // If found TX
                            if (l_tx){
                                // Check for time from
                                if(a_time_from && l_tx->header.ts_created < a_time_from)
                                        continue;

                                // Check for time to
                                if(a_time_to && l_tx->header.ts_created > a_time_to)
                                        continue;

                                if(a_search_type == TX_SEARCH_TYPE_CELL_SPENT || a_search_type == TX_SEARCH_TYPE_NET_SPENT ){
                                    dap_hash_fast_t * l_tx_hash = dap_chain_node_datum_tx_calc_hash(l_tx);
                                    bool l_is_spent = dap_chain_ledger_tx_spent_find_by_hash(l_ledger,l_tx_hash);
                                    DAP_DELETE(l_tx_hash);
                                    if(!l_is_spent)
                                        continue;
                                }

                                // Go through all items
                                uint32_t l_tx_items_pos = 0, l_tx_items_size = l_tx->header.tx_items_size;
                                int l_item_idx = 0;
                                while (l_tx_items_pos < l_tx_items_size) {
                                    uint8_t *l_item = l_tx->tx_items + l_tx_items_pos;
                                    int l_item_size = dap_chain_datum_item_tx_get_size(l_item);
                                    if(!l_item_size)
                                        break;
                                    // check type
                                    dap_chain_tx_item_type_t l_item_type = dap_chain_datum_tx_item_get_type(l_item);
                                    switch (l_item_type){
                                        case TX_ITEM_TYPE_IN_COND:{
                                            dap_chain_tx_in_cond_t * l_tx_in_cond = (dap_chain_tx_in_cond_t *) l_item;
                                            dap_chain_datum_tx_spends_item_t  *l_tx_prev_out_item = NULL;
                                            HASH_FIND(hh, l_ret->tx_outs, &l_tx_in_cond->header.tx_prev_hash,sizeof(l_tx_in_cond->header.tx_prev_hash), l_tx_prev_out_item);

                                            if (l_tx_prev_out_item){ // we found previous out_cond with target srv_uid
                                                dap_chain_datum_tx_spends_item_t *l_item_in = DAP_NEW_Z(dap_chain_datum_tx_spends_item_t);
                                                if (!l_item_in) {
                                                    log_it(L_ERROR, "Memory allocation error in dap_chain_net_get_tx_cond_all_with_spends_by_srv_uid");
                                                    DAP_DEL_Z(l_datums);
                                                    return NULL;
                                                }
                                                size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
                                                dap_chain_datum_tx_t * l_tx_dup = DAP_DUP_SIZE(l_tx,l_tx_size);
                                                dap_hash_fast(l_tx_dup,l_tx_size, &l_item_in->tx_hash);

                                                l_item_in->tx = l_tx_dup;
                                                // Calc same offset from tx duplicate
                                                l_item_in->in_cond = (dap_chain_tx_in_cond_t*) (l_tx_dup->tx_items + l_tx_items_pos);
                                                HASH_ADD(hh,l_ret->tx_ins, tx_hash, sizeof(dap_chain_hash_fast_t), l_item_in);

                                                // Link previous out with current in
                                                l_tx_prev_out_item->tx_next = l_tx_dup;
                                            }
                                        }break;
                                        case TX_ITEM_TYPE_OUT_COND:{
                                            dap_chain_tx_out_cond_t * l_tx_out_cond = (dap_chain_tx_out_cond_t *)l_item;
                                            if(l_tx_out_cond->header.srv_uid.uint64 == a_srv_uid.uint64){
                                                dap_chain_datum_tx_spends_item_t * l_item = DAP_NEW_Z(dap_chain_datum_tx_spends_item_t);
                                                if (!l_item) {
                                                    log_it(L_ERROR, "Memory allocation error in dap_chain_net_get_tx_cond_all_with_spends_by_srv_uid");
                                                    DAP_DEL_Z(l_datums);
                                                    return NULL;
                                                }
                                                size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
                                                dap_chain_datum_tx_t * l_tx_dup = DAP_DUP_SIZE(l_tx,l_tx_size);
                                                dap_hash_fast(l_tx,l_tx_size, &l_item->tx_hash);
                                                l_item->tx = l_tx_dup;
                                                // Calc same offset from tx duplicate
                                                l_item->out_cond = (dap_chain_tx_out_cond_t*) (l_tx_dup->tx_items + l_tx_items_pos);

                                                HASH_ADD(hh,l_ret->tx_outs, tx_hash, sizeof(dap_chain_hash_fast_t), l_item);
                                                break; // We're seaching only for one specified OUT_COND output per transaction
                                            }
                                        } break;
                                        default:;
                                    }

                                    l_tx_items_pos += l_item_size;
                                    l_item_idx++;
                                }
                            }
                        }
                        DAP_DEL_Z(l_datums);
                        // go to next atom
                        l_atom = l_chain->callback_atom_iter_get_next(l_atom_iter, &l_atom_size);

                    }
                    l_chain->callback_atom_iter_delete(l_atom_iter);
                }
            }
        } break;

    }
    return l_ret;

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
        case TX_SEARCH_TYPE_CELL_UNSPENT:
        case TX_SEARCH_TYPE_NET:
        case TX_SEARCH_TYPE_CELL:
        case TX_SEARCH_TYPE_LOCAL:
        case TX_SEARCH_TYPE_CELL_SPENT:
        case TX_SEARCH_TYPE_NET_SPENT: {
            // pass all chains
            for ( dap_chain_t * l_chain = a_net->pub.chains; l_chain; l_chain = l_chain->next){
                dap_chain_cell_t * l_cell, *l_cell_tmp;
                // Go through all cells
                HASH_ITER(hh,l_chain->cells,l_cell, l_cell_tmp){
                    dap_chain_atom_iter_t * l_atom_iter = l_chain->callback_atom_iter_create(l_chain,l_cell->id, false  );
                    // try to find transaction in chain ( inside shard )
                    size_t l_atom_size = 0;
                    dap_chain_atom_ptr_t l_atom = l_chain->callback_atom_iter_get_first(l_atom_iter, &l_atom_size);

                    // Check atoms in chain
                    while(l_atom && l_atom_size) {
                        size_t l_datums_count = 0;
                        dap_chain_datum_t **l_datums = l_chain->callback_atom_get_datums(l_atom, l_atom_size, &l_datums_count);
                        // transaction
                        dap_chain_datum_tx_t *l_tx = NULL;

                        for (size_t i = 0; i < l_datums_count; i++) {
                            // Check if its transaction
                            if (l_datums && (l_datums[i]->header.type_id == DAP_CHAIN_DATUM_TX)) {
                                l_tx = (dap_chain_datum_tx_t *) l_datums[i]->data;
                            }

                            // If found TX

                            if ( l_tx ) {
                                   a_tx_callback(a_net, l_tx, a_arg);
                            }
                        }
                        DAP_DEL_Z(l_datums);
                        // go to next atom
                        l_atom = l_chain->callback_atom_iter_get_next(l_atom_iter, &l_atom_size);
                    }
                    l_chain->callback_atom_iter_delete(l_atom_iter);
                }
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
static void s_get_tx_cond_chain_callback(dap_chain_net_t* a_net, dap_chain_datum_tx_t *a_tx, void *a_arg)
{
    struct get_tx_cond_all_from_tx * l_args = (struct get_tx_cond_all_from_tx* ) a_arg;
    dap_hash_fast_t * l_tx_hash = dap_chain_node_datum_tx_calc_hash(a_tx);
    if( l_args->ret ){
        int l_item_idx = 0;
        byte_t *l_tx_item;

        // Get items from transaction
        while ((l_tx_item = dap_chain_datum_tx_item_get(a_tx, &l_item_idx, TX_ITEM_TYPE_IN_COND , NULL)) != NULL){
            dap_chain_tx_in_cond_t * l_in_cond = (dap_chain_tx_in_cond_t *) l_tx_item;
            if(dap_hash_fast_compare(&l_in_cond->header.tx_prev_hash, &l_args->tx_last_hash) &&
                    (uint32_t)l_args->tx_last_cond_idx == l_in_cond->header.tx_out_prev_idx ){ // Found output
                // We're the next tx in tx cond chain
                l_args->ret = dap_list_append(l_args->ret, a_tx);
            }
            l_item_idx++;
        }
    }else if(dap_hash_fast_compare(l_tx_hash,l_args->tx_begin_hash)){
        // Found condition
        int l_item_idx = 0;
        byte_t *l_tx_item;

        // Get items from transaction
        while ((l_tx_item = dap_chain_datum_tx_item_get(a_tx, &l_item_idx, TX_ITEM_TYPE_OUT_COND , NULL)) != NULL){
            dap_chain_tx_out_cond_t * l_out_cond = (dap_chain_tx_out_cond_t *) l_tx_item;
            if ( l_out_cond->header.srv_uid.uint64 == l_args->srv_uid.uint64 ){ // We found output with target service uuid
                l_args->tx_last = a_tx; // Record current transaction as the last in tx chain
                memcpy(&l_args->tx_last_hash, l_tx_hash, sizeof(*l_tx_hash)); // Record current hash
                l_args->tx_last_cond_idx = l_item_idx;
                l_args->ret = dap_list_append(NULL, a_tx);
                break;
            }
        }
    }
    DAP_DELETE(l_tx_hash);
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
        log_it (L_ERROR, "Memory allocation error in dap_chain_net_get_tx_cond_all_for_addr");
        return NULL;
    }
    l_args->tx_begin_hash = a_tx_hash;
    l_args->srv_uid = a_srv_uid;
    dap_chain_net_get_tx_all(a_net,TX_SEARCH_TYPE_NET,s_get_tx_cond_chain_callback, l_args);
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
static void s_get_tx_cond_all_for_addr_callback(dap_chain_net_t* a_net, dap_chain_datum_tx_t *a_datum_tx, void *a_arg)
{
    struct get_tx_cond_all_for_addr * l_args = (struct get_tx_cond_all_for_addr* ) a_arg;
    int l_item_idx = 0;
    dap_chain_datum_tx_item_t *l_tx_item;
    bool l_tx_for_addr = false; // TX with output related with our address
    bool l_tx_from_addr = false; // TX with input that take assets from our address
    //const char *l_tx_from_addr_token = NULL;
    bool l_tx_collected = false;  // We already collected this TX in return list

    // Get in items to detect is in or in_cond from target address
    while ((l_tx_item = (dap_chain_datum_tx_item_t *) dap_chain_datum_tx_item_get(a_datum_tx, &l_item_idx, TX_ITEM_TYPE_ANY , NULL)) != NULL){
        switch (l_tx_item->type){
            case TX_ITEM_TYPE_IN:{
                dap_chain_tx_in_t * l_in = (dap_chain_tx_in_t *) l_tx_item;
                if( l_tx_from_addr) // Already detected thats spends from addr
                    break;
                dap_chain_tx_t * l_tx = dap_chain_tx_hh_find( l_args->tx_all_hh, &l_in->header.tx_prev_hash);
                if( l_tx ){ // Its input thats closing output for target address - we note it
                    l_tx_from_addr = true;
                    //l_tx_from_addr_token = dap_chain_ledger_tx_get_token_ticker_by_hash(a_net->pub.ledger, &l_tx->hash);
                }
            }break;
            case TX_ITEM_TYPE_IN_COND:{
                if(l_tx_collected) // Already collected
                    break;
                dap_chain_tx_in_cond_t * l_in_cond = (dap_chain_tx_in_cond_t *) l_tx_item;
                dap_chain_tx_t * l_tx = dap_chain_tx_hh_find( l_args->tx_all_hh, &l_in_cond->header.tx_prev_hash);
                if( l_tx ){ // Its input thats closing conditioned tx related with target address, collect it
                    //dap_chain_tx_t *l_tx_add = dap_chain_tx_wrap_packed(a_datum_tx);
                    l_args->ret = dap_list_append(l_args->ret, a_datum_tx);
                    l_tx_collected = true;
                }
            }break;
        }
        l_item_idx++;
    }

    // Get out items from transaction
    while ((l_tx_item = (dap_chain_datum_tx_item_t *) dap_chain_datum_tx_item_get(a_datum_tx, &l_item_idx, TX_ITEM_TYPE_OUT_ALL , NULL)) != NULL){
        switch (l_tx_item->type){
            case TX_ITEM_TYPE_OUT:{
                if(l_tx_for_addr) // Its already added
                    break;
                dap_chain_tx_out_t * l_out = (dap_chain_tx_out_t*) l_tx_item;
                if ( memcmp(&l_out->addr, l_args->addr, sizeof(*l_args->addr)) == 0){ // Its our address tx
                    dap_chain_tx_t * l_tx = dap_chain_tx_wrap_packed(a_datum_tx);
                    dap_chain_tx_hh_add(l_args->tx_all_hh, l_tx);
                    l_tx_for_addr = true;
                }
            }break;
            case TX_ITEM_TYPE_OUT_EXT:{
                if(l_tx_for_addr) // Its already added
                    break;
                dap_chain_tx_out_ext_t * l_out = (dap_chain_tx_out_ext_t*) l_tx_item;
                if ( memcmp(&l_out->addr, l_args->addr, sizeof(*l_args->addr)) == 0){ // Its our address tx
                    dap_chain_tx_t * l_tx = dap_chain_tx_wrap_packed(a_datum_tx);
                    dap_chain_tx_hh_add(l_args->tx_all_hh, l_tx);
                    l_tx_for_addr = true;
                }
            }break;
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
        l_item_idx++;
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
        log_it (L_ERROR, "Memory allocation error in dap_chain_net_get_tx_cond_all_for_addr");
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
    dap_ledger_t * l_ledger = a_net->pub.ledger;
    dap_list_t * l_ret = NULL;

    switch (a_search_type) {
        case TX_SEARCH_TYPE_NET:
        case TX_SEARCH_TYPE_CELL:
        case TX_SEARCH_TYPE_LOCAL:
        case TX_SEARCH_TYPE_CELL_SPENT:
        case TX_SEARCH_TYPE_NET_SPENT: {
            // pass all chains
            for ( dap_chain_t * l_chain = a_net->pub.chains; l_chain; l_chain = l_chain->next){
                dap_chain_cell_t * l_cell, *l_cell_tmp;
                // Go through all cells
                HASH_ITER(hh,l_chain->cells,l_cell, l_cell_tmp){
                    dap_chain_atom_iter_t * l_atom_iter = l_chain->callback_atom_iter_create(l_chain,l_cell->id, false  );
                    // try to find transaction in chain ( inside shard )
                    size_t l_atom_size = 0;
                    dap_chain_atom_ptr_t l_atom = l_chain->callback_atom_iter_get_first(l_atom_iter, &l_atom_size);

                    // Check atoms in chain
                    while(l_atom && l_atom_size) {
                        size_t l_datums_count = 0;
                        dap_chain_datum_t **l_datums = l_chain->callback_atom_get_datums(l_atom, l_atom_size, &l_datums_count);
                        // transaction
                        dap_chain_datum_tx_t *l_tx = NULL;

                        for (size_t i = 0; i < l_datums_count; i++) {
                            // Check if its transaction
                            if (l_datums && (l_datums[i]->header.type_id == DAP_CHAIN_DATUM_TX)) {
                                l_tx = (dap_chain_datum_tx_t *)l_datums[i]->data;
                            }

                            // If found TX
                            if (l_tx){
                                // Check for time from
                                if(a_time_from && l_tx->header.ts_created < a_time_from)
                                        continue;

                                // Check for time to
                                if(a_time_to && l_tx->header.ts_created > a_time_to)
                                        continue;

                                if(a_search_type == TX_SEARCH_TYPE_CELL_SPENT || a_search_type == TX_SEARCH_TYPE_NET_SPENT ){
                                    dap_hash_fast_t * l_tx_hash = dap_chain_node_datum_tx_calc_hash(l_tx);
                                    bool l_is_spent = dap_chain_ledger_tx_spent_find_by_hash(l_ledger,l_tx_hash);
                                    DAP_DELETE(l_tx_hash);
                                    if(!l_is_spent)
                                        continue;
                                }
                                // Check for OUT_COND items
                                dap_list_t *l_list_out_cond_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_OUT_COND , NULL);
                                if(l_list_out_cond_items){
                                    dap_list_t *l_list_cur = l_list_out_cond_items;
                                    while(l_list_cur){ // Go through all cond items
                                        dap_chain_tx_out_cond_t * l_tx_out_cond = (dap_chain_tx_out_cond_t *)l_list_cur->data;
                                        if(l_tx_out_cond) // If we found cond out with target srv_uid
                                            if(l_tx_out_cond->header.srv_uid.uint64 == a_srv_uid.uint64)
                                                l_ret = dap_list_append(l_ret,
                                                                        DAP_DUP_SIZE(l_tx, dap_chain_datum_tx_get_size(l_tx)));
                                        l_list_cur = dap_list_next(l_list_cur);
                                    }
                                    dap_list_free(l_list_out_cond_items);
                                }
                            }
                        }
                        DAP_DEL_Z(l_datums);
                        // go to next atom
                        l_atom = l_chain->callback_atom_iter_get_next(l_atom_iter, &l_atom_size);
                    }
                    l_chain->callback_atom_iter_delete(l_atom_iter);
                }
            }
        } break;

        case TX_SEARCH_TYPE_NET_UNSPENT:
        case TX_SEARCH_TYPE_CELL_UNSPENT:
            l_ret = dap_chain_ledger_tx_cache_find_out_cond_all(l_ledger, a_srv_uid);
            break;
    }
    return l_ret;

}


/**
 * @brief Summarize all tx inputs
 * @param a_net
 * @param a_tx
 * @return
 */
uint256_t dap_chain_net_get_tx_total_value(dap_chain_net_t * a_net, dap_chain_datum_tx_t * a_tx)
{
    uint256_t l_ret = {0};
    int l_item_idx = 0;
    dap_chain_tx_in_t *l_in_item = NULL;
    do {
        l_in_item = (dap_chain_tx_in_t*) dap_chain_datum_tx_item_get(a_tx, &l_item_idx, TX_ITEM_TYPE_IN , NULL);
        l_item_idx++;
        if(l_in_item ) {
            //const char *token = l_out_cond_item->subtype.srv_xchange.token;
            dap_chain_datum_tx_t * l_tx_prev = dap_chain_net_get_tx_by_hash(a_net,&l_in_item->header.tx_prev_hash, TX_SEARCH_TYPE_NET_SPENT);
            if(l_tx_prev){
                int l_tx_prev_out_index = l_in_item->header.tx_out_prev_idx;
                dap_chain_tx_out_t *  l_tx_prev_out =(dap_chain_tx_out_t *)
                        dap_chain_datum_tx_item_get(l_tx_prev,&l_tx_prev_out_index, TX_ITEM_TYPE_OUT,NULL);
                if ((uint32_t)l_tx_prev_out_index == l_in_item->header.tx_out_prev_idx && l_tx_prev_out) {
                    uint256_t l_in_value = l_tx_prev_out->header.value;
                    if(SUM_256_256(l_in_value,l_ret, &l_ret )!= 0)
                        log_it(L_ERROR, "Overflow on inputs values calculation (summing)");
                }else{
                    log_it(L_WARNING, "Can't find item with index %d in prev tx hash", l_tx_prev_out_index);
                }
            }else
                log_it(L_WARNING, "Can't find prev tx hash");
        }
    } while(l_in_item);
    return l_ret;
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
    case TX_SEARCH_TYPE_CELL:
    case TX_SEARCH_TYPE_LOCAL:
    case TX_SEARCH_TYPE_CELL_SPENT:
    case TX_SEARCH_TYPE_NET_SPENT:
        // pass all chains
        for (dap_chain_t * l_chain = a_net->pub.chains; l_chain; l_chain = l_chain->next) {
            if (!l_chain->callback_datum_find_by_hash)
                return NULL;
            // try to find transaction in chain ( inside shard )
            int l_ret_code;
            dap_chain_datum_t *l_datum = l_chain->callback_datum_find_by_hash(l_chain, a_tx_hash, NULL, &l_ret_code);
            if (!l_datum || l_datum->header.type_id != DAP_CHAIN_DATUM_TX)
                continue;
            if ((a_search_type == TX_SEARCH_TYPE_CELL_SPENT ||
                    a_search_type == TX_SEARCH_TYPE_NET_SPENT) &&
                    (!dap_chain_ledger_tx_spent_find_by_hash(l_ledger, a_tx_hash)))
                return NULL;
            return (dap_chain_datum_tx_t *)l_datum->data;
        }
    case TX_SEARCH_TYPE_NET_UNSPENT:
    case TX_SEARCH_TYPE_CELL_UNSPENT:
        return dap_chain_ledger_tx_find_by_hash(l_ledger, a_tx_hash);
    default:;
    }
    return NULL;
}

static struct net_fee {
    dap_chain_net_id_t net_id;
    uint256_t value;            // Network fee value
    dap_chain_addr_t fee_addr;  // Addr collector
    UT_hash_handle hh;
} *s_net_fees = NULL; // Governance statements for networks

bool dap_chain_net_tx_get_fee(dap_chain_net_id_t a_net_id, uint256_t *a_value, dap_chain_addr_t *a_addr)
{
    struct net_fee *l_net_fee;
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_net_id);

    if (!l_net){
        log_it(L_WARNING, "Can't find net with id 0x%016"DAP_UINT64_FORMAT_x"", a_net_id.uint64);
        return false;
    }

    HASH_FIND(hh, s_net_fees, &a_net_id, sizeof(dap_chain_net_id_t), l_net_fee);
    if (!l_net_fee || IS_ZERO_256(l_net_fee->value))
        return false;
    if (a_value)
        *a_value = l_net_fee->value;
    if (a_addr)
        *a_addr = l_net_fee->fee_addr;
    return true;
}

bool dap_chain_net_tx_add_fee(dap_chain_net_id_t a_net_id, uint256_t a_value, dap_chain_addr_t a_addr)
{
    struct net_fee *l_net_fee = NULL;
    bool l_found = false;
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_net_id);

    if (!l_net){
        log_it(L_WARNING, "Can't find net with id 0x%016"DAP_UINT64_FORMAT_x"", a_net_id.uint64);
        return false;
    }

    HASH_FIND(hh, s_net_fees, &a_net_id, sizeof(dap_chain_net_id_t), l_net_fee);

    if (l_net_fee)
        l_found = true;
    else
        l_net_fee = DAP_NEW(struct net_fee);
    l_net_fee->net_id = a_net_id;
    l_net_fee->value = a_value;
    l_net_fee->fee_addr = a_addr;

    if (!l_found)
        HASH_ADD(hh, s_net_fees, net_id, sizeof(dap_chain_net_id_t), l_net_fee);

    dap_chain_ledger_set_fee(l_net->pub.ledger, a_value, a_addr);

    return true;
}
