/*
 * Authors:
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2019
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

#include <stdbool.h>
#include <stddef.h>
#include <pthread.h>

#include "dap_chain_wallet.h"
#include "dap_common.h"
#include "dap_enc_base58.h"
#include "dap_strfuncs.h"
#include "dap_string.h"
#include "dap_list.h"
#include "dap_hash.h"

#include "dap_chain_cell.h"
#include "dap_chain_datum.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_node_cli.h"
#include "dap_chain_node_cli_cmd_tx.h"

#define LOG_TAG "chain_node_cli_cmd_tx"

#include "uthash.h"
// for dap_db_history_filter()
typedef struct dap_tx_data {
    dap_chain_hash_fast_t tx_hash;
    char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    dap_chain_datum_t *datum;
    UT_hash_handle hh;
    //useless
    char tx_hash_str[70];
    dap_chain_addr_t addr;
} dap_tx_data_t;

typedef struct dap_chain_tx_hash_processed_ht{
    dap_chain_hash_fast_t hash;
    UT_hash_handle hh;
} dap_chain_tx_hash_processed_ht_t;

/**
 * @brief s_dap_chain_tx_hash_processed_ht_free
 * free l_current_hash->hash, l_current_hash, l_hash_processed
 * @param l_hash_processed dap_chain_tx_hash_processed_ht_t
 */
static void s_dap_chain_tx_hash_processed_ht_free(dap_chain_tx_hash_processed_ht_t *l_hash_processed)
{
    dap_chain_tx_hash_processed_ht_t *l_tmp, *l_current_hash;
    HASH_ITER(hh, l_hash_processed, l_current_hash, l_tmp)
        DAP_FREE(l_current_hash);
}

/**
 * @brief _dap_chain_datum_tx_out_data
 *
 * @param a_datum
 * @param a_ledger
 * @param a_str_out
 * @param a_hash_out_type
 * @param save_processed_tx
 * @param a_tx_hash_processed
 * @param l_tx_num
 */

static bool s_dap_chain_datum_tx_out_data(dap_chain_datum_tx_t *a_datum,
                                          dap_ledger_t *a_ledger,
                                          dap_string_t *a_str_out,
                                          const char *a_hash_out_type,
                                          dap_chain_hash_fast_t *a_tx_hash)
{
    const char *l_ticker = NULL;
    if (a_ledger) {
            l_ticker = dap_chain_ledger_tx_get_token_ticker_by_hash(a_ledger, a_tx_hash);
        if (!l_ticker)
            return false;
    }
    dap_chain_datum_dump_tx(a_datum, l_ticker, a_str_out, a_hash_out_type, a_tx_hash);
    return true;
}

// for dap_db_history_tx & dap_db_history_addr()
static dap_chain_datum_t* get_prev_tx(dap_tx_data_t *a_tx_data)
{
    if(!a_tx_data)
        return NULL;
    dap_chain_datum_t *l_datum = a_tx_data->datum;
    return l_datum;
}


/**
 * @brief dap_db_history_tx
 * Get data according the history log
 *
 * return history string
 * @param a_tx_hash
 * @param a_chain
 * @param a_hash_out_type
 * @return char*
 */
char* dap_db_history_tx(dap_chain_hash_fast_t* a_tx_hash, dap_chain_t * a_chain, const char *a_hash_out_type)
{
    dap_string_t *l_str_out = dap_string_new(NULL);

    bool l_tx_hash_found = false;
    dap_tx_data_t *l_tx_data_hash = NULL;
    dap_chain_cell_t *l_cell = a_chain->cells;
    do {
        // load transactions
        dap_chain_atom_iter_t *l_atom_iter = a_chain->callback_atom_iter_create(a_chain, l_cell->id, 0);
        size_t l_atom_size = 0;
        dap_chain_atom_ptr_t l_atom = a_chain->callback_atom_iter_get_first(l_atom_iter, &l_atom_size);

        while(l_atom && l_atom_size) {
            dap_chain_datum_t *l_datum = (dap_chain_datum_t*) l_atom;
            if (!l_datum || (l_datum->header.type_id != DAP_CHAIN_DATUM_TX)) {
                // go to next transaction
                l_atom = a_chain->callback_atom_iter_get_next(l_atom_iter, &l_atom_size);
                continue;
            }



            dap_tx_data_t *l_tx_data = NULL;

            // transaction
            dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t*) l_datum->data;

            // find Token items - present in emit transaction
            dap_list_t *l_list_tx_token;
            l_list_tx_token = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_TOKEN, NULL);

            // find OUT items
            bool l_type_256 = false;
            dap_list_t *l_list_out_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_OUT_OLD, NULL);
            if (!l_list_out_items) {
                l_list_out_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_OUT, NULL);
                l_type_256 = true;
            }

            dap_list_t *l_list_tmp = l_list_out_items;

            while(l_list_tmp) {

                const dap_chain_tx_out_t *l_tx_out_256  = (const dap_chain_tx_out_t*) l_list_tmp->data;
                const dap_chain_tx_out_old_t *l_tx_out = (const dap_chain_tx_out_old_t*) l_list_tmp->data;

                // save OUT item l_tx_out - only for first OUT item
                if(!l_tx_data) {
                    // save tx hash
                    l_tx_data = DAP_NEW_Z(dap_tx_data_t);
                    dap_chain_hash_fast_t l_tx_hash;
                    dap_hash_fast(l_tx, dap_chain_datum_tx_get_size(l_tx), &l_tx_hash);
                    l_tx_data->tx_hash = l_tx_hash;
                    l_tx_data->addr = l_type_256 ? l_tx_out_256->addr : l_tx_out->addr;
                    dap_chain_hash_fast_to_str(&l_tx_data->tx_hash, l_tx_data->tx_hash_str,
                            sizeof(l_tx_data->tx_hash_str));
                    l_tx_data->datum = DAP_DUP_SIZE(l_datum, l_atom_size);
                    // save token name
                    if(l_list_tx_token) {
                        dap_chain_tx_token_t *tk = l_list_tx_token->data;
                        memcpy(l_tx_data->token_ticker, tk->header.ticker, sizeof(l_tx_data->token_ticker));
                    }
                    else {

                        // find IN items
                        dap_list_t *l_list_in_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_IN, NULL);
                        dap_list_t *l_list_tmp_in = l_list_in_items;
                        // find token_ticker in prev OUT items
                        while(l_list_tmp_in) {
                            const dap_chain_tx_in_t *l_tx_in =
                                    (const dap_chain_tx_in_t*) l_list_tmp_in->data;
                            dap_chain_hash_fast_t tx_prev_hash = l_tx_in->header.tx_prev_hash;

                            //find prev OUT item
                            dap_tx_data_t *l_tx_data_prev = NULL;
                            HASH_FIND(hh, l_tx_data_hash, &tx_prev_hash, sizeof(dap_chain_hash_fast_t),
                                    l_tx_data_prev);
                            if(l_tx_data_prev != NULL) {
                                // fill token in l_tx_data from prev transaction
                                if(l_tx_data) {
                                    // get token from prev tx
                                    memcpy(l_tx_data->token_ticker, l_tx_data_prev->token_ticker,
                                            sizeof(l_tx_data->token_ticker));
                                    break;
                                }
                                l_list_tmp_in = dap_list_next(l_list_tmp_in);
                            }
                        }
                        if(l_list_in_items)
                            dap_list_free(l_list_in_items);
                    }
                    HASH_ADD(hh, l_tx_data_hash, tx_hash, sizeof(dap_chain_hash_fast_t), l_tx_data);
                }
                l_list_tmp = dap_list_next(l_list_tmp);
            }

            if(l_list_out_items)
                dap_list_free(l_list_out_items);

            // calc hash
            dap_chain_hash_fast_t l_tx_hash;
            dap_hash_fast(l_tx, dap_chain_datum_tx_get_size(l_tx), &l_tx_hash);
            // search tx with a_tx_hash
            if(!dap_hash_fast_compare(a_tx_hash, &l_tx_hash)) {
                // go to next transaction
                l_atom = a_chain->callback_atom_iter_get_next(l_atom_iter, &l_atom_size);
                continue;
            }
            // found a_tx_hash now

            // transaction time
            if(l_tx->header.ts_created > 0) {
                time_t rawtime = (time_t) l_tx->header.ts_created;
                struct tm l_timeinfo = {0};
                localtime_r(&rawtime, &l_timeinfo);
                dap_string_append_printf(l_str_out, " %s", asctime(&l_timeinfo));
            }

            // find all OUT items in transaction
            if ( l_type_256 )
                l_list_out_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_OUT, NULL);
            else
                l_list_out_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_OUT_OLD, NULL);
            l_list_tmp = l_list_out_items;

            while(l_list_tmp) {
                const dap_chain_tx_out_t *l_tx_out_256 = (const dap_chain_tx_out_t*) l_list_tmp->data;
                const dap_chain_tx_out_old_t *l_tx_out = (const dap_chain_tx_out_old_t*) l_list_tmp->data;
                //dap_tx_data_t *l_tx_data_prev = NULL;

                const char *l_token_str = NULL;
                if(l_tx_data)
                    l_token_str = l_tx_data->token_ticker;
                char *l_dst_to_str = (l_tx_out) ? dap_chain_addr_to_str(&l_tx_out->addr) :
                                                (l_tx_out_256) ? dap_chain_addr_to_str(&l_tx_out_256->addr) : NULL;

                if(l_tx_out || l_tx_out_256) {
                    if(l_type_256) { // 256
                        char *l_balance = dap_chain_balance_print(l_tx_out_256->header.value);
                        dap_string_append_printf(l_str_out, " OUT 256bit item %s %s to %s\n",
                                l_balance,
                                dap_strlen(l_token_str) > 0 ? l_token_str : "?",
                                l_dst_to_str ? l_dst_to_str : "?"
                                               );
                        DAP_DELETE(l_balance);
                    }
                    else
                        dap_string_append_printf(l_str_out, " OUT item %"DAP_UINT64_FORMAT_U" %s to %s\n",
                            l_tx_out->header.value,
                            dap_strlen(l_token_str) > 0 ? l_token_str : "?",
                            l_dst_to_str ? l_dst_to_str : "?"
                        );
                }
                DAP_DELETE(l_dst_to_str);
                l_list_tmp = dap_list_next(l_list_tmp);
            }

            // find all IN items in transaction
            dap_list_t *l_list_in_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_IN, NULL);
            l_list_tmp = l_list_in_items;
            // find cur addr in prev OUT items
            while(l_list_tmp) {
                const dap_chain_tx_in_t *l_tx_in = (const dap_chain_tx_in_t*) l_list_tmp->data;
                dap_chain_hash_fast_t tx_prev_hash = l_tx_in->header.tx_prev_hash;
                char l_tx_hash_str[70];
                char *tx_hash_base58_str = NULL;
                if(!dap_hash_fast_is_blank(&tx_prev_hash)){
                    tx_hash_base58_str = dap_enc_base58_from_hex_str_to_str( l_tx_data->tx_hash_str);
                    dap_chain_hash_fast_to_str(&tx_prev_hash, l_tx_hash_str, sizeof(l_tx_hash_str));

                }
                else{
                    strcpy(l_tx_hash_str, "Null");
                    tx_hash_base58_str = dap_strdup("Null");
                }
                if(!dap_strcmp(a_hash_out_type,"hex"))
                    dap_string_append_printf(l_str_out, " IN item \n  prev tx_hash %s\n", l_tx_hash_str);
                else
                    dap_string_append_printf(l_str_out, " IN item \n  prev tx_hash %s\n", tx_hash_base58_str);
                DAP_DELETE(tx_hash_base58_str);


                //find prev OUT item
                dap_tx_data_t *l_tx_data_prev = NULL;
                HASH_FIND(hh, l_tx_data_hash, &tx_prev_hash, sizeof(dap_chain_hash_fast_t), l_tx_data_prev);
                if(l_tx_data_prev != NULL) {

                    dap_chain_datum_t *l_datum_prev = get_prev_tx(l_tx_data_prev);
                    dap_chain_datum_tx_t *l_tx_prev =
                            l_datum_prev ? (dap_chain_datum_tx_t*) l_datum_prev->data : NULL;

                    if ( l_type_256 ) { // 256
                        // find OUT items in prev datum
                        dap_list_t *l_list_out_prev_items = dap_chain_datum_tx_items_get(l_tx_prev,
                                TX_ITEM_TYPE_OUT, NULL);
                        // find OUT item for IN item;
                        dap_list_t *l_list_out_prev_item = dap_list_nth(l_list_out_prev_items,
                                l_tx_in->header.tx_out_prev_idx);
                        dap_chain_tx_out_t *l_tx_prev_out =
                                l_list_out_prev_item ? (dap_chain_tx_out_t*)l_list_out_prev_item->data : NULL;
                        // print value from prev out item
                        char *l_balance = l_tx_prev_out ? dap_chain_balance_print(l_tx_prev_out->header.value) : NULL;
                        dap_string_append_printf(l_str_out, "  prev OUT 256bit item value=%s",
                                l_balance ? l_balance : "0");
                        DAP_DEL_Z(l_balance);
                    } else {
                        dap_list_t *l_list_out_prev_items = dap_chain_datum_tx_items_get(l_tx_prev,
                                TX_ITEM_TYPE_OUT_OLD, NULL);
                        dap_list_t *l_list_out_prev_item = dap_list_nth(l_list_out_prev_items,
                                l_tx_in->header.tx_out_prev_idx);
                        dap_chain_tx_out_old_t *l_tx_prev_out =
                                l_list_out_prev_item ? (dap_chain_tx_out_old_t*)l_list_out_prev_item->data : NULL;
                        dap_string_append_printf(l_str_out, "  prev OUT item value=%"DAP_UINT64_FORMAT_U,
                                l_tx_prev_out ? l_tx_prev_out->header.value : 0);

                    }
                }
                dap_string_append_printf(l_str_out, "\n");
                l_list_tmp = dap_list_next(l_list_tmp);
            }

            if(l_list_tx_token)
                dap_list_free(l_list_tx_token);
            if(l_list_out_items)
                dap_list_free(l_list_out_items);
            if(l_list_in_items)
                dap_list_free(l_list_in_items);
            l_tx_hash_found = true;
            break;

            // go to next transaction
            //l_atom = a_chain->callback_atom_iter_get_next(l_atom_iter);
            //l_atom_size = a_chain->callback_atom_get_size(l_atom);
        }
        a_chain->callback_atom_iter_delete(l_atom_iter);

        // delete hashes
        dap_tx_data_t *l_iter_current, *l_item_tmp;
        HASH_ITER(hh, l_tx_data_hash , l_iter_current, l_item_tmp)
        {
            HASH_DEL(l_tx_data_hash, l_iter_current);
            // delete datum
            DAP_DELETE(l_iter_current->datum);
            // delete struct
            DAP_DELETE(l_iter_current);
        }
        l_cell = l_cell->hh.next;
    } while (l_cell);

    // if no history
    if(!l_str_out->len)
        dap_string_append(l_str_out, "empty");
    char *l_ret_str = l_str_out ? dap_string_free(l_str_out, false) : NULL;
    return l_ret_str;
}


/**
 * @brief dap_db_history_addr
 * Get data according the history log
 *
 * return history string
 * @param a_addr
 * @param a_chain
 * @param a_hash_out_type
 * @return char*
 */

static void s_tx_header_print(dap_string_t *a_str_out, dap_chain_tx_hash_processed_ht_t *a_tx_data_ht,
                              dap_chain_datum_tx_t *a_tx, dap_chain_atom_iter_t *a_atom_iter,
                              const char *a_hash_out_type, dap_ledger_t *a_ledger,
                              dap_chain_hash_fast_t *a_tx_hash)
{
    bool l_declined = false;
    // transaction time
    char l_time_str[32] = "unknown";                                /* Prefill string */
    if (a_tx->header.ts_created) {
        uint64_t l_ts = a_tx->header.ts_created;
        dap_ctime_r(&l_ts, l_time_str);                             /* Convert ts to  Sat May 17 01:17:08 2014 */
    }
    dap_hash_fast(a_tx, dap_chain_datum_tx_get_size(a_tx), a_tx_hash);
    dap_chain_tx_hash_processed_ht_t *l_tx_data = NULL;
    HASH_FIND(hh, a_tx_data_ht, a_tx_hash, sizeof(*a_tx_hash), l_tx_data);
    if (l_tx_data)  // this tx already present in ledger (double)
        l_declined = true;
    else {
        l_tx_data = DAP_NEW_Z(dap_chain_tx_hash_processed_ht_t);
        l_tx_data->hash = *a_tx_hash;
        HASH_ADD(hh, a_tx_data_ht, hash, sizeof(*a_tx_hash), l_tx_data);
        const char *l_token_ticker = dap_chain_ledger_tx_get_token_ticker_by_hash(a_ledger, a_tx_hash);
        if (!l_token_ticker)
            l_declined = true;
    }
    char *l_tx_hash_str, *l_atom_hash_str;
    if (!dap_strcmp(a_hash_out_type, "hex")) {
        l_tx_hash_str = dap_chain_hash_fast_to_str_new(a_tx_hash);
        l_atom_hash_str = dap_chain_hash_fast_to_str_new(a_atom_iter->cur_hash);
    } else {
        l_tx_hash_str = dap_enc_base58_encode_hash_to_str(a_tx_hash);
        l_atom_hash_str = dap_enc_base58_encode_hash_to_str(a_atom_iter->cur_hash);
    }
    dap_string_append_printf(a_str_out, "%s TX hash %s (atom %s) \n\t%s", l_declined ? "DECLINED" : "ACCEPTED",
                                                                          l_tx_hash_str, l_atom_hash_str, l_time_str);
    DAP_DELETE(l_tx_hash_str);
    DAP_DELETE(l_atom_hash_str);
}

char *dap_db_history_addr(dap_chain_addr_t *a_addr, dap_chain_t *a_chain, const char *a_hash_out_type)
{

    dap_string_t *l_str_out = dap_string_new(NULL);

    dap_chain_tx_hash_processed_ht_t *l_tx_data_ht = NULL;
    // load transactions
    dap_chain_atom_iter_t *l_atom_iter = a_chain->callback_atom_iter_create(a_chain, a_chain->cells->id, 0);
    size_t l_atom_size=0;
    dap_chain_atom_ptr_t l_atom = a_chain->callback_atom_iter_get_first(l_atom_iter, &l_atom_size);
    if (!l_atom) {
        return NULL;
    }

    if (!a_chain->callback_atom_get_datums) {
        log_it(L_WARNING, "Not defined callback_atom_get_datums for chain \"%s\"", a_chain->name);
        return NULL;
    }
    dap_ledger_t *l_ledger = dap_chain_net_by_id(a_chain->net_id)->pub.ledger;

    while (l_atom && l_atom_size) {
        size_t l_datums_count = 0;
        dap_chain_datum_t **l_datums = a_chain->callback_atom_get_datums(l_atom, l_atom_size, &l_datums_count);
        for (size_t d = 0; d < l_datums_count; d++) {
            dap_chain_datum_t *l_datum = l_datums ? l_datums[d] : NULL;
            if (!l_datum || l_datum->header.type_id != DAP_CHAIN_DATUM_TX) {
                // go to next datum
                continue;
            }
            // it's a transaction
            dap_hash_fast_t l_tx_hash;
            dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t *)l_datum->data;
            dap_list_t *l_list_in_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_IN_ALL, NULL);
            if (!l_list_in_items) { // a bad tx
                continue;
            }
            dap_chain_addr_t *l_src_addr = NULL;
            bool l_base_tx = false;
            const char *l_src_token = NULL;
            int l_src_subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_UNDEFINED;
            for (dap_list_t *it = l_list_in_items; it; it = it->next) {
                dap_chain_hash_fast_t *l_tx_prev_hash;
                int l_tx_prev_out_idx;
                dap_chain_datum_tx_t *l_tx_prev = NULL;
                if (*(byte_t *)l_list_in_items->data == TX_ITEM_TYPE_IN) {
                    dap_chain_tx_in_t *l_tx_in = (dap_chain_tx_in_t *)l_list_in_items->data;
                    l_tx_prev_hash = &l_tx_in->header.tx_prev_hash;
                    l_tx_prev_out_idx = l_tx_in->header.tx_out_prev_idx;
                } else { // TX_ITEM_TYPE_IN_COND
                    dap_chain_tx_in_cond_t *l_tx_in_cond = (dap_chain_tx_in_cond_t *)l_list_in_items->data;
                    l_tx_prev_hash = &l_tx_in_cond->header.tx_prev_hash;
                    l_tx_prev_out_idx = l_tx_in_cond->header.tx_out_prev_idx;
                }
                if (dap_hash_fast_is_blank(l_tx_prev_hash)) {
                    l_base_tx = true;
                    dap_chain_tx_token_t *l_token = (dap_chain_tx_token_t *)dap_chain_datum_tx_item_get(
                                                                            l_tx, NULL, TX_ITEM_TYPE_TOKEN, NULL);
                    if (l_token)
                        l_src_token = l_token->header.ticker;
                    break;
                }
                l_tx_prev = a_chain->callback_tx_find_by_hash(a_chain, l_tx_prev_hash);
                if (l_tx_prev) {
                    uint8_t *l_prev_out_union = dap_chain_datum_tx_item_get_nth(l_tx_prev, TX_ITEM_TYPE_OUT_ALL, l_tx_prev_out_idx);
                    if (!l_prev_out_union)
                        continue;
                    switch (*l_prev_out_union) {
                    case TX_ITEM_TYPE_OUT:
                        l_src_addr = &((dap_chain_tx_out_t *)l_prev_out_union)->addr;
                        break;
                    case TX_ITEM_TYPE_OUT_EXT:
                        l_src_addr = &((dap_chain_tx_out_ext_t *)l_prev_out_union)->addr;
                        l_src_token = (const char *)(((dap_chain_tx_out_ext_t *)l_prev_out_union)->token);
                        break;
                    case TX_ITEM_TYPE_OUT_COND:
                        l_src_subtype = ((dap_chain_tx_out_cond_t *)l_prev_out_union)->header.subtype;
                    default:
                        break;
                    }
                }
                if (!l_src_token)
                    l_src_token = dap_chain_ledger_tx_get_token_ticker_by_hash(l_ledger, l_tx_prev_hash);
                if (l_src_addr && memcmp(l_src_addr, a_addr, sizeof(dap_chain_addr_t)))
                    break;  //it's not our addr
            }
            dap_list_free(l_list_in_items);
            // find OUT items
            bool l_header_printed = false;
            dap_list_t *l_list_out_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_OUT_ALL, NULL);
            for (dap_list_t *l_list_out = l_list_out_items; l_list_out; l_list_out = dap_list_next(l_list_out)) {
                dap_chain_addr_t *l_dst_addr = NULL;
                uint8_t l_type = *(uint8_t *)l_list_out->data;
                uint256_t l_value;
                switch (l_type) {
                case TX_ITEM_TYPE_OUT:
                    l_dst_addr = &((dap_chain_tx_out_t *)l_list_out->data)->addr;
                    l_value = ((dap_chain_tx_out_t *)l_list_out->data)->header.value;
                    break;
                case TX_ITEM_TYPE_OUT_EXT:
                    l_dst_addr = &((dap_chain_tx_out_ext_t *)l_list_out->data)->addr;
                    l_value = ((dap_chain_tx_out_ext_t *)l_list_out->data)->header.value;
                    break;
                case TX_ITEM_TYPE_OUT_COND:
                    l_value = ((dap_chain_tx_out_cond_t *)l_list_out->data)->header.value;
                default:
                    break;
                }
                if (l_src_addr && l_dst_addr && !memcmp(l_dst_addr, l_src_addr, sizeof(dap_chain_addr_t)))
                    continue;   // send to self
                if (l_src_addr && !memcmp(l_src_addr, a_addr, sizeof(dap_chain_addr_t))) {
                    if (!l_header_printed) {
                        s_tx_header_print(l_str_out, l_tx_data_ht, l_tx, l_atom_iter, a_hash_out_type, l_ledger, &l_tx_hash);
                        l_header_printed = true;
                    }
                    //const char *l_token_ticker = dap_chain_ledger_tx_get_token_ticker_by_hash(l_ledger, &l_tx_hash);
                    const char *l_dst_addr_str = l_dst_addr ? dap_chain_addr_to_str(l_dst_addr)
                                                            : dap_chain_tx_out_cond_subtype_to_str(
                                                                  ((dap_chain_tx_out_cond_t *)l_list_out->data)->header.subtype);
                    char *l_value_str = dap_chain_balance_print(l_value);
                    char *l_coins_str = dap_chain_balance_to_coins(l_value);
                    dap_string_append_printf(l_str_out, "\tsend %s (%s) %s to %s\n",
                                             l_coins_str,
                                             l_value_str,
                                             l_src_token ? l_src_token : "UNKNOWN",
                                             l_dst_addr_str);
                    if (l_dst_addr)
                        DAP_DELETE(l_dst_addr_str);
                    DAP_DELETE(l_value_str);
                    DAP_DELETE(l_coins_str);
                }
                if (l_dst_addr && !memcmp(l_dst_addr, a_addr, sizeof(dap_chain_addr_t))) {
                    if (!l_header_printed) {
                        s_tx_header_print(l_str_out, l_tx_data_ht, l_tx, l_atom_iter, a_hash_out_type, l_ledger, &l_tx_hash);
                        l_header_printed = true;
                    }
                    const char *l_dst_token = (l_type == TX_ITEM_TYPE_OUT_EXT) ?
                                (const char *)(((dap_chain_tx_out_ext_t *)l_list_out->data)->token) : NULL;
                    const char *l_src_addr_str = l_base_tx ? "emission"
                                                           : (l_src_addr ? dap_chain_addr_to_str(l_src_addr)
                                                                         : dap_chain_tx_out_cond_subtype_to_str(
                                                                               l_src_subtype));
                    char *l_value_str = dap_chain_balance_print(l_value);
                    char *l_coins_str = dap_chain_balance_to_coins(l_value);
                    dap_string_append_printf(l_str_out, "\trecv %s (%s) %s from %s\n",
                                             l_coins_str,
                                             l_value_str,
                                             l_dst_token ? l_dst_token :
                                                           (l_src_token ? l_src_token : "UNKNOWN"),
                                             l_src_addr_str);
                    if (l_src_addr)
                        DAP_DELETE(l_src_addr_str);
                    DAP_DELETE(l_value_str);
                    DAP_DELETE(l_coins_str);
                }
            }
            dap_list_free(l_list_out_items);

        }
        DAP_DELETE(l_datums);
        // go to next atom (event or block)
        l_atom = a_chain->callback_atom_iter_get_next(l_atom_iter, &l_atom_size);
    }
    a_chain->callback_atom_iter_delete(l_atom_iter);
    // delete hashes
    s_dap_chain_tx_hash_processed_ht_free(l_tx_data_ht);
    // if no history
    if(!l_str_out->len)
        dap_string_append(l_str_out, "\tempty");
    char *l_ret_str = l_str_out ? dap_string_free(l_str_out, false) : NULL;
    return l_ret_str;
}

/**
 * @brief char* dap_db_history_token_list
 *
 * @param a_chain
 * @param a_token_name
 * @param a_hash_out_type
 * @param a_token_num
 * @return char*
 */
static char* dap_db_history_token_list(dap_chain_t * a_chain, const char *a_token_name, const char *a_hash_out_type, size_t *a_token_num)
{
    dap_string_t *l_str_out = dap_string_new(NULL);
    *a_token_num  = 0;
    size_t l_atom_size = 0;
    dap_chain_cell_t *l_cell = a_chain->cells;
    do {
        dap_chain_atom_iter_t *l_atom_iter = a_chain->callback_atom_iter_create(a_chain, l_cell->id, 0);
        if(!a_chain->callback_atom_get_datums) {
            log_it(L_DEBUG, "Not defined callback_atom_get_datums for chain \"%s\"", a_chain->name);
            return NULL ;
        }
        for (dap_chain_atom_ptr_t l_atom = a_chain->callback_atom_iter_get_first(l_atom_iter, &l_atom_size);
            l_atom && l_atom_size; l_atom = a_chain->callback_atom_iter_get_next(l_atom_iter, &l_atom_size)) {
            size_t l_datums_count = 0;
            dap_chain_datum_t **l_datums = a_chain->callback_atom_get_datums(l_atom, l_atom_size, &l_datums_count);
            for(size_t l_datum_n = 0; l_datum_n < l_datums_count; l_datum_n++) {
                dap_chain_datum_t *l_datum = l_datums[l_datum_n];
                if (!l_datum || l_datum->header.type_id != DAP_CHAIN_DATUM_TOKEN_DECL)
                    continue;
                if (a_token_name && dap_strcmp(((dap_chain_datum_token_t *)l_datum->data)->ticker, a_token_name))
                    continue;
                dap_chain_datum_dump(l_str_out, l_datum, a_hash_out_type);
                (*a_token_num)++;
            }
            DAP_DELETE(l_datums);
        }
        a_chain->callback_atom_iter_delete(l_atom_iter);
        l_cell = l_cell->hh.next;
    } while (l_cell);
    char *l_ret_str = l_str_out ? dap_string_free(l_str_out, false) : NULL;
    return l_ret_str;
}


/**
 * @brief dap_db_history_filter
 * Get data according the history log
 *
 * return history string
 * @param a_chain
 * @param a_ledger
 * @param a_filter_token_name
 * @param a_filtr_addr_base58
 * @param a_hash_out_type
 * @param a_datum_start
 * @param a_datum_end
 * @param a_total_datums
 * @param a_tx_hash_processed
 * @return char*
 */
static char* dap_db_history_filter(dap_chain_t * a_chain, dap_ledger_t *a_ledger, const char *a_filter_token_name, const char *a_filtr_addr_base58, const char *a_hash_out_type, long a_datum_start, long a_datum_end, long *a_total_datums, dap_chain_tx_hash_processed_ht_t *a_tx_hash_processed)
{
    if (!a_chain->callback_atom_get_datums) {
        log_it(L_WARNING, "Not defined callback_atom_get_datums for chain \"%s\"", a_chain->name);
        return NULL;
    }
    dap_string_t *l_str_out = dap_string_new(NULL);
    // list all transactions
    dap_tx_data_t *l_tx_data_hash = NULL;
    dap_chain_cell_t *l_cell = a_chain->cells;

    do {
        // load transactions
        size_t l_atom_size = 0;
        dap_chain_atom_iter_t *l_atom_iter = a_chain->callback_atom_iter_create(a_chain, l_cell->id, 0);
        size_t l_datum_num = 0, l_token_num = 0, l_emission_num = 0, l_tx_num = 0;
        size_t l_datum_num_global = a_total_datums ? *a_total_datums : 0;
        for (dap_chain_atom_ptr_t l_atom = a_chain->callback_atom_iter_get_first(l_atom_iter, &l_atom_size); l_atom && l_atom_size;
                l_atom = a_chain->callback_atom_iter_get_next(l_atom_iter, &l_atom_size)) {
            size_t l_datums_count = 0;
            dap_chain_datum_t **l_datums = a_chain->callback_atom_get_datums(l_atom, l_atom_size, &l_datums_count);
            if (!l_datums || !l_datums_count)
                continue;
            for(size_t l_datum_n = 0; l_datum_n < l_datums_count; l_datum_n++) {
                dap_chain_datum_t *l_datum = l_datums[l_datum_n];
                if(!l_datum)
                    continue;
                char l_time_str[70];
                // get time of create datum
                if(dap_time_to_str_rfc822(l_time_str, 71, l_datum->header.ts_create) < 1)
                    l_time_str[0] = '\0';
                switch (l_datum->header.type_id) {

                // token
                case DAP_CHAIN_DATUM_TOKEN_DECL: {
                    // no token necessary for addr
                    if (a_filtr_addr_base58)
                        break;
                    dap_chain_datum_token_t *l_token = (dap_chain_datum_token_t*) l_datum->data;
                    //if(a_datum_start < 0 || (l_datum_num >= a_datum_start && l_datum_num < a_datum_end))
                    // datum out of page
                    if(a_datum_start >= 0 && (l_datum_num+l_datum_num_global < (size_t)a_datum_start || l_datum_num+l_datum_num_global >= (size_t)a_datum_end)){
                        l_token_num++;
                        break;
                    }
                    if(!a_filter_token_name || !dap_strcmp(l_token->ticker, a_filter_token_name)) {
                        dap_chain_datum_dump(l_str_out, l_datum, a_hash_out_type);
                        dap_string_append(l_str_out, "\n");
                        l_token_num++;
                    }
                } break;

                // emission
                case DAP_CHAIN_DATUM_TOKEN_EMISSION: {
                    // datum out of page
                    if(a_datum_start >= 0 && (l_datum_num+l_datum_num_global < (size_t)a_datum_start || l_datum_num+l_datum_num_global >= (size_t)a_datum_end)) {
                         l_emission_num++;
                         break;
                    }
                    dap_chain_datum_token_emission_t *l_token_em =  (dap_chain_datum_token_emission_t *)l_datum->data;
                    if(!a_filter_token_name || !dap_strcmp(l_token_em->hdr.ticker, a_filter_token_name)) {
                        char * l_token_emission_address_str = dap_chain_addr_to_str(&(l_token_em->hdr.address));
                        // filter for addr
                        if (a_filtr_addr_base58 && dap_strcmp(a_filtr_addr_base58, l_token_emission_address_str)) {
                             break;
                        }
                        dap_chain_datum_dump(l_str_out, l_datum, a_hash_out_type);
                        dap_string_append(l_str_out, "\n");
                        l_emission_num++;
                    }
                } break;

                // transaction
                case DAP_CHAIN_DATUM_TX:{
                    // datum out of page
                    if(a_datum_start >= 0 && (l_datum_num+l_datum_num_global < (size_t)a_datum_start || l_datum_num+l_datum_num_global >= (size_t)a_datum_end)) {
                        l_tx_num++;
                        break;
                    }
                    dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t*)l_datum->data;
                    //calc tx hash
                    dap_chain_hash_fast_t l_tx_hash;
                    dap_hash_fast(l_tx, dap_chain_datum_tx_get_size(l_tx), &l_tx_hash);
                    char *l_token = dap_chain_ledger_tx_get_token_ticker_by_hash(a_ledger, &l_tx_hash);
                    if (a_filter_token_name && dap_strcmp(a_filter_token_name, l_token)) {
                        break;
                    }
                    dap_chain_tx_hash_processed_ht_t *l_sht = NULL;
                    HASH_FIND(hh, a_tx_hash_processed, &l_tx_hash, sizeof(dap_chain_hash_fast_t), l_sht);
                    if (l_sht != NULL ||
                            !s_dap_chain_datum_tx_out_data(l_tx, a_ledger, l_str_out, a_hash_out_type, &l_tx_hash)) {
                        l_datum_num--;
                        break;
                    }
                    l_sht = DAP_NEW_Z(dap_chain_tx_hash_processed_ht_t);
                    l_sht->hash = l_tx_hash;
                    HASH_ADD(hh, a_tx_hash_processed, hash, sizeof(dap_chain_hash_fast_t), l_sht);
                    l_tx_num++;
                } break;

                default:
                    dap_string_append_printf(l_str_out, "unknown datum type=%d\n", l_datum->header.type_id);
                    break;
                }
                l_datum_num++;
            }
        }
        a_chain->callback_atom_iter_delete(l_atom_iter);
        //total
        dap_string_append_printf(l_str_out,
                "---------------\ntokens: %zu\nemissions: %zu\ntransactions: %zu\ntotal datums: %zu", l_token_num,
                l_emission_num, l_tx_num, l_datum_num);

        // return total datums
        if(a_total_datums)
            *a_total_datums = l_datum_num;
        // delete hashes
        dap_tx_data_t *l_iter_current, *l_item_tmp;
        HASH_ITER(hh, l_tx_data_hash , l_iter_current, l_item_tmp)
        {
            HASH_DEL(l_tx_data_hash, l_iter_current);
            // delete datum
            DAP_DELETE(l_iter_current->datum);
            // delete struct
            DAP_DELETE(l_iter_current);
        }
        l_cell = l_cell->hh.next;
    } while (l_cell);

    // if no history
    if(!l_str_out->len)
        dap_string_append(l_str_out, "empty");
    char *l_ret_str = l_str_out ? dap_string_free(l_str_out, false) : NULL;
    return l_ret_str;
}


/**
 * @brief com_ledger
 * ledger command
 * @param a_argc
 * @param a_argv
 * @param a_arg_func
 * @param a_str_reply
 * @return int
 */
int com_ledger(int a_argc, char ** a_argv, char **a_str_reply)
{
    enum { CMD_NONE, CMD_LIST, CMD_LEDGER_HISTORY, CMD_TX_INFO };
    int arg_index = 1;
    const char *l_addr_base58 = NULL;
    const char *l_wallet_name = NULL;
    const char *l_net_str = NULL;
    const char *l_chain_str = NULL;
    const char *l_tx_hash_str = NULL;

    dap_chain_t * l_chain = NULL;
    dap_chain_net_t * l_net = NULL;

    const char * l_hash_out_type = NULL;
    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "invalid parameter -H, valid values: -H <hex | base58>");
        return -1;
    }

    //switch ledger params list | tx | info
    int l_cmd = CMD_NONE;
    if (dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "list", NULL)){
        l_cmd = CMD_LIST;
    } else if (dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "tx", NULL)){
        l_cmd = CMD_LEDGER_HISTORY;
    } else if (dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "info", NULL))
        l_cmd = CMD_TX_INFO;

    bool l_is_all = dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-all", NULL);

    arg_index++;

    // command tx_history
    if(l_cmd == CMD_LEDGER_HISTORY) {
        dap_chain_node_cli_find_option_val(a_argv, 0, a_argc, "-addr", &l_addr_base58);
        dap_chain_node_cli_find_option_val(a_argv, 0, a_argc, "-w", &l_wallet_name);
        dap_chain_node_cli_find_option_val(a_argv, 0, a_argc, "-net", &l_net_str);
        //dap_chain_node_cli_find_option_val(a_argv, 0, a_argc, "-chain", &l_chain_str);
        dap_chain_node_cli_find_option_val(a_argv, 0, a_argc, "-tx", &l_tx_hash_str);
        dap_chain_tx_hash_processed_ht_t *l_list_tx_hash_processd = NULL;

        if(!l_is_all && !l_addr_base58 && !l_wallet_name && !l_tx_hash_str) {
            dap_chain_node_cli_set_reply_text(a_str_reply, "command requires parameter '-all' or '-addr' or '-w'");
            return -1;
        }
        // Select chain network
        if(!l_net_str) {
            dap_chain_node_cli_set_reply_text(a_str_reply, "command requires parameter '-net'");
            return -2;
        } else {
            if((l_net = dap_chain_net_by_name(l_net_str)) == NULL) { // Can't find such network
                dap_chain_node_cli_set_reply_text(a_str_reply,
                        "command requires parameter '-net' to be valid chain network name");
                return -3;
            }
        }

        dap_chain_hash_fast_t l_tx_hash;
        if(l_tx_hash_str) {
            if (dap_chain_hash_fast_from_str(l_tx_hash_str, &l_tx_hash)) {
                l_tx_hash_str = NULL;
                dap_chain_node_cli_set_reply_text(a_str_reply, "tx hash not recognized");
                return -1;
            }
//        char hash_str[99];
//        dap_chain_hash_fast_to_str(&l_tx_hash, hash_str,99);
//        int gsdgsd=523;
        }
        dap_chain_addr_t *l_addr = NULL;
        // if need addr
        if(l_wallet_name || l_addr_base58) {
            if(l_wallet_name) {
                const char *c_wallets_path = dap_chain_wallet_get_path(g_config);
                dap_chain_wallet_t * l_wallet = dap_chain_wallet_open(l_wallet_name, c_wallets_path);
                if(l_wallet) {
                    dap_chain_addr_t *l_addr_tmp = (dap_chain_addr_t *) dap_chain_wallet_get_addr(l_wallet,
                            l_net->pub.id);
                    l_addr = DAP_NEW_S(dap_chain_addr_t);
                    memcpy(l_addr, l_addr_tmp, sizeof(dap_chain_addr_t));
                    dap_chain_wallet_close(l_wallet);
                }
            }
            if(!l_addr && l_addr_base58) {
                l_addr = dap_chain_addr_from_str(l_addr_base58);
            }
            if(!l_addr && !l_tx_hash_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "wallet address not recognized");
                return -1;
            }
        }
        dap_string_t *l_str_ret = dap_string_new(NULL); //char *l_str_ret = NULL;

        char *l_str_out = NULL;
        dap_ledger_t *l_ledger = dap_chain_ledger_by_net_name(l_net_str);
        if(l_is_all) {
            // without filters
            //l_str_out = dap_db_history_filter(l_chain_cur, l_ledger, NULL, NULL, l_hash_out_type, -1, 0, NULL, l_list_tx_hash_processd);
            dap_string_append_printf(l_str_ret, "all history:\n%s\n", l_str_out ? l_str_out : " empty");
        }
        else {/*
            l_str_out = l_tx_hash_str ?
                                        dap_db_history_tx(&l_tx_hash, l_chain_cur, l_hash_out_type) :
                                        dap_ledger_token_tx_item_list(l_ledger,l_addr,l_hash_out_type);
                                        //dap_db_history_addr(l_addr, l_chain_cur, l_hash_out_type);
            */
            l_str_out = dap_ledger_token_tx_item_list(l_ledger,l_addr,l_hash_out_type);
            if(l_tx_hash_str) {
                dap_string_append_printf(l_str_ret, "history for tx hash %s:\n%s\n", l_tx_hash_str,
                        l_str_out ? l_str_out : " empty");
            }
            else if(l_addr) {
                char *l_addr_str = dap_chain_addr_to_str(l_addr);
                dap_string_append_printf(l_str_ret, "history for addr %s:\n%s\n", l_addr_str,
                        l_str_out ? l_str_out : " empty");
                DAP_DELETE(l_addr_str);
            }
        }
        DAP_DELETE(l_str_out);
        s_dap_chain_tx_hash_processed_ht_free(l_list_tx_hash_processd);
        // all chain
        if(!l_chain)
            dap_chain_enum_unlock();
        dap_chain_node_cli_set_reply_text(a_str_reply, l_str_ret->str);
        dap_string_free(l_str_ret, true);
        return 0;
    }
    else if(l_cmd == CMD_LIST){
        enum {SUBCMD_NONE, SUBCMD_LIST_COIN, SUB_CMD_LIST_LEDGER_THRESHOLD, SUB_CMD_LIST_LEDGER_BALANCE, SUB_CMD_LIST_LEDGER_THRESHOLD_WITH_HASH};
        int l_sub_cmd = SUBCMD_NONE;
        dap_chain_hash_fast_t l_tx_threshold_hash;
        if (dap_chain_node_cli_find_option_val(a_argv, 2, 3, "coins", NULL ))
            l_sub_cmd = SUBCMD_LIST_COIN;
        if (dap_chain_node_cli_find_option_val(a_argv, 2, 3, "balance", NULL ))
            l_sub_cmd = SUB_CMD_LIST_LEDGER_BALANCE;
        if (dap_chain_node_cli_find_option_val(a_argv, 2, a_argc, "threshold", NULL)){
            l_sub_cmd = SUB_CMD_LIST_LEDGER_THRESHOLD;
            const char* l_tx_threshold_hash_str = NULL;
            dap_chain_node_cli_find_option_val(a_argv, 3, a_argc, "-hash", &l_tx_threshold_hash_str);
            if (l_tx_threshold_hash_str){
                l_sub_cmd = SUB_CMD_LIST_LEDGER_THRESHOLD_WITH_HASH;
                if (dap_chain_hash_fast_from_str(l_tx_threshold_hash_str, &l_tx_threshold_hash)){
                    l_tx_hash_str = NULL;
                    dap_chain_node_cli_set_reply_text(a_str_reply, "tx threshold hash not recognized");
                    return -1;
                }
            }
        }
        if (l_sub_cmd == SUBCMD_NONE) {
            dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'list' requires subcommands 'coins' or 'threshold'");
            return -5;
        }
        dap_chain_node_cli_find_option_val(a_argv, 0, a_argc, "-net", &l_net_str);
        if (l_net_str == NULL){
            dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'list' requires key -net");
            return -1;
        }
        dap_ledger_t *l_ledger = dap_chain_ledger_by_net_name(l_net_str);
        if (l_ledger == NULL){
            dap_chain_node_cli_set_reply_text(a_str_reply, "Can't get ledger for net %s", l_net_str);
            return -2;
        }
        if (l_sub_cmd == SUB_CMD_LIST_LEDGER_THRESHOLD){
            dap_string_t *l_str_ret = dap_chain_ledger_threshold_info(l_ledger);
            if (l_str_ret){
                dap_chain_node_cli_set_reply_text(a_str_reply, l_str_ret->str);
                dap_string_free(l_str_ret, true);
            }

            return 0;
        }
        if (l_sub_cmd == SUB_CMD_LIST_LEDGER_THRESHOLD_WITH_HASH){
            dap_string_t *l_str_ret = dap_chain_ledger_threshold_hash_info(l_ledger, &l_tx_threshold_hash);
            if (l_str_ret){
                dap_chain_node_cli_set_reply_text(a_str_reply, l_str_ret->str);
                dap_string_free(l_str_ret, true);
            }
            return 0;
        }
        if (l_sub_cmd == SUB_CMD_LIST_LEDGER_BALANCE){
            dap_string_t *l_str_ret = dap_chain_ledger_balance_info(l_ledger);
            if (l_str_ret){
                dap_chain_node_cli_set_reply_text(a_str_reply, l_str_ret->str);
                dap_string_free(l_str_ret, true);
            }

            return 0;
        }
        dap_string_t *l_str_ret = dap_string_new("");
        dap_list_t *l_token_list = dap_chain_ledger_token_info(l_ledger);
        dap_string_append_printf(l_str_ret, "Found %u tokens in %s ledger\n", dap_list_length(l_token_list), l_net_str);
        for (dap_list_t *l_list = l_token_list; l_list; l_list = dap_list_next(l_list)) {
            dap_string_append(l_str_ret, (char *)l_list->data);
        }
        dap_list_free_full(l_token_list, free);
        dap_chain_node_cli_set_reply_text(a_str_reply, l_str_ret->str);
        dap_string_free(l_str_ret, true);
        return 0;
    } else if (l_cmd == CMD_TX_INFO){
        //GET hash
        dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-hash", &l_tx_hash_str);
        //get net
        dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_str);
        //get search type
        int l_unspent_flag = dap_chain_node_cli_check_option(a_argv, arg_index, a_argc, "-unspent");
        //check input
        if (l_tx_hash_str == NULL){
            dap_chain_node_cli_set_reply_text(a_str_reply, "Subcommand 'info' requires key -hash");
            return -1;
        }
        if (l_net_str == NULL){
            dap_chain_node_cli_set_reply_text(a_str_reply, "Subcommand 'info' requires key -net");
            return -2;
        }
        dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
        if (!l_net) {
            dap_chain_node_cli_set_reply_text(a_str_reply, "Can't find net %s", l_net_str);
            return -2;
        }
        dap_chain_hash_fast_t l_tx_hash = { 0 };
        if (dap_chain_hash_fast_from_str(l_tx_hash_str, &l_tx_hash)) {
            dap_chain_node_cli_set_reply_text(a_str_reply, "Can't get hash_fast from %s", l_tx_hash_str);
            return -4;
        }
        dap_chain_datum_tx_t *l_datum_tx = dap_chain_net_get_tx_by_hash(l_net, &l_tx_hash,
                                                                        l_unspent_flag >= 0 ? TX_SEARCH_TYPE_NET_UNSPENT : TX_SEARCH_TYPE_NET);
        if (l_datum_tx == NULL){
            dap_chain_node_cli_set_reply_text(a_str_reply, "Can't get datum from transaction hash %s", l_tx_hash_str);
            return -5;
        }
        dap_string_t *l_str = dap_string_new("");
        s_dap_chain_datum_tx_out_data(l_datum_tx, l_net->pub.ledger, l_str, l_hash_out_type, &l_tx_hash);
        dap_chain_node_cli_set_reply_text(a_str_reply, l_str->str);
        dap_string_free(l_str, true);
    }
    else{
        dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'ledger' requires parameter 'list' or 'tx' or 'info'");
        return -6;
    }
    return 0;
}


/**
 * @brief com_token
 * token command
 * @param a_argc
 * @param a_argv
 * @param a_arg_func
 * @param a_str_reply
 * @return int
 */
int com_token(int a_argc, char ** a_argv, char **a_str_reply)
{
    enum { CMD_NONE, CMD_LIST, CMD_INFO, CMD_TX };
    int arg_index = 1;
    const char *l_net_str = NULL;
    dap_chain_net_t * l_net = NULL;
    dap_chain_tx_hash_processed_ht_t *l_list_tx_hash_processd = NULL;

    const char * l_hash_out_type = NULL;
    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "base58";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "invalid parameter -H, valid values: -H <hex | base58>");
        return -1;
    }

    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_str);
    // Select chain network
    if(!l_net_str) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "command requires parameter '-net'");
        return -2;
    } else {
        if((l_net = dap_chain_net_by_name(l_net_str)) == NULL) { // Can't find such network
            dap_chain_node_cli_set_reply_text(a_str_reply,
                    "command requires parameter '-net' to be valid chain network name");
            return -3;
        }
    }

    int l_cmd = CMD_NONE;
    if (dap_chain_node_cli_find_option_val(a_argv, 1, 2, "list", NULL))
        l_cmd = CMD_LIST;
    else if (dap_chain_node_cli_find_option_val(a_argv, 1, 2, "info", NULL))
        l_cmd = CMD_INFO;
    else if (dap_chain_node_cli_find_option_val(a_argv, 1, 2, "tx", NULL))
            l_cmd = CMD_TX;
    // token list
    if(l_cmd == CMD_LIST) {
        dap_string_t *l_str_out = dap_string_new(NULL);
        size_t l_token_num_total = 0;
        // get first chain
        void *l_chain_tmp = (void*)0x1;
        dap_chain_t *l_chain_cur = dap_chain_enum(&l_chain_tmp);
        while(l_chain_cur) {
            // only selected net
            if(l_net->pub.id.uint64 == l_chain_cur->net_id.uint64) {
                size_t l_token_num = 0;
                char *token_list_str = dap_db_history_token_list(l_chain_cur, NULL, l_hash_out_type, &l_token_num);
                if(token_list_str)
                    dap_string_append(l_str_out, token_list_str);
                l_token_num_total += l_token_num;
            }
            // next chain
            dap_chain_enum_unlock();
            l_chain_cur = dap_chain_enum(&l_chain_tmp);
        }
        dap_chain_enum_unlock();
        //total
        dap_string_append_printf(l_str_out, "---------------\ntokens: %zu\n", l_token_num_total);
        dap_chain_node_cli_set_reply_text(a_str_reply, l_str_out->str);
        dap_string_free(l_str_out, true);
        return 0;

    }
    // token info
    else if(l_cmd == CMD_INFO) {
        const char *l_token_name_str = NULL;
        dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-name", &l_token_name_str);
        if(!l_token_name_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "command requires parameter '-name' <token name>");
                return -4;
            }

            dap_string_t *l_str_out = dap_string_new(NULL);
            size_t l_token_num_total = 0;
            // get first chain
            void *l_chain_tmp = (void*)0x1;
            dap_chain_t *l_chain_cur = dap_chain_enum(&l_chain_tmp);
            while(l_chain_cur) {
                // only selected net
                if(l_net->pub.id.uint64 == l_chain_cur->net_id.uint64) {
                    size_t l_token_num = 0;
                    // filter - token name
                    char *token_list_str = dap_db_history_token_list(l_chain_cur, l_token_name_str, l_hash_out_type, &l_token_num);
                    if(token_list_str)
                        dap_string_append(l_str_out, token_list_str);
                    l_token_num_total += l_token_num;
                }
                // next chain
                dap_chain_enum_unlock();
                l_chain_cur = dap_chain_enum(&l_chain_tmp);
            }
            dap_chain_enum_unlock();
            if(!l_token_num_total)
                dap_string_append_printf(l_str_out, "token '%s' not found\n", l_token_name_str);
            dap_chain_node_cli_set_reply_text(a_str_reply, l_str_out->str);
            dap_string_free(l_str_out, true);
            return 0;

    }
    // command tx history
    else if(l_cmd == CMD_TX) {

        enum { SUBCMD_TX_NONE, SUBCMD_TX_ALL, SUBCMD_TX_ADDR };
        // find subcommand
        int l_subcmd = CMD_NONE;
        const char *l_addr_base58_str = NULL;
        const char *l_wallet_name = NULL;
        if(dap_chain_node_cli_find_option_val(a_argv, 2, a_argc, "all", NULL))
            l_subcmd = SUBCMD_TX_ALL;
        else if(dap_chain_node_cli_find_option_val(a_argv, 2, a_argc, "-addr", &l_addr_base58_str))
            l_subcmd = SUBCMD_TX_ADDR;
        else if(dap_chain_node_cli_find_option_val(a_argv, 2, a_argc, "-wallet", &l_wallet_name))
            l_subcmd = SUBCMD_TX_ADDR;

        const char *l_token_name_str = NULL;
        const char *l_page_start_str = NULL;
        const char *l_page_size_str = NULL;
        const char *l_page_str = NULL;
        dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-name", &l_token_name_str);
        dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-page_start", &l_page_start_str);
        dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-page_size", &l_page_size_str);
        dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-page", &l_page_str);
        if(!l_token_name_str) {
            dap_chain_node_cli_set_reply_text(a_str_reply, "command requires parameter '-name' <token name>");
            return -4;
        }
        long l_page_start = -1;// not used if =-1
        long l_page_size = 10;
        long l_page = 2;
        long l_cur_datum = 0;
        if(l_page_start_str)
            l_page_start = strtol(l_page_start_str, NULL, 10);
        if(l_page_size_str) {
            l_page_size = strtol(l_page_size_str, NULL, 10);
            if(l_page_size < 1)
                l_page_size = 1;
        }
        if(l_page_str) {
            l_page = strtol(l_page_str, NULL, 10);
            if(l_page < 1)
                l_page = 1;
        }


         // tx all
        if(l_subcmd == SUBCMD_TX_ALL) {
            dap_string_t *l_str_out = dap_string_new(NULL);
            // get first chain
            void *l_chain_tmp = (void*) 0x1;
            dap_chain_t *l_chain_cur = dap_chain_enum(&l_chain_tmp);
            while(l_chain_cur) {
                // only selected net
                if(l_net->pub.id.uint64 == l_chain_cur->net_id.uint64) {
                    long l_chain_datum = l_cur_datum;
                    dap_ledger_t *l_ledger = dap_chain_ledger_by_net_name(l_net_str);
                    char *l_datum_list_str = dap_db_history_filter(l_chain_cur, l_ledger, l_token_name_str, NULL,
                            l_hash_out_type, l_page_start * l_page_size, (l_page_start+l_page)*l_page_size, &l_chain_datum, l_list_tx_hash_processd);
                    if(l_datum_list_str) {
                        l_cur_datum += l_chain_datum;
                        dap_string_append_printf(l_str_out, "Chain: %s\n", l_chain_cur->name);
                        dap_string_append_printf(l_str_out, "%s\n\n", l_datum_list_str);
                        DAP_DELETE(l_datum_list_str);
                    }
                }
                // next chain
                dap_chain_enum_unlock();
                l_chain_cur = dap_chain_enum(&l_chain_tmp);
            }
            dap_chain_enum_unlock();
            s_dap_chain_tx_hash_processed_ht_free(l_list_tx_hash_processd);
            dap_chain_node_cli_set_reply_text(a_str_reply, l_str_out->str);
            dap_string_free(l_str_out, true);
            return 0;
        }
        // tx -addr or tx -wallet
        else if(l_subcmd == SUBCMD_TX_ADDR) {
            // parse addr from -addr <addr> or -wallet <wallet>
            dap_chain_addr_t *l_addr_base58 = NULL;
            if(l_addr_base58_str) {
                //l_addr_base58 = dap_strdup(l_addr_base58_str);
                l_addr_base58 = dap_chain_addr_from_str(l_addr_base58_str);
            }
            else if(l_wallet_name) {
                const char *c_wallets_path = dap_chain_wallet_get_path(g_config);
                dap_chain_wallet_t * l_wallet = dap_chain_wallet_open(l_wallet_name, c_wallets_path);
                if(l_wallet) {
                    dap_chain_addr_t *l_addr_base58 = (dap_chain_addr_t *) dap_chain_wallet_get_addr(l_wallet,
                            l_net->pub.id);
                    dap_chain_wallet_close(l_wallet);
                }
                else {
                    dap_chain_node_cli_set_reply_text(a_str_reply, "wallet '%s' not found", l_wallet_name);
                    return -2;
                }
            }
            if(!l_addr_base58) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "address not recognized");
                return -3;
            }

            dap_string_t *l_str_out = dap_string_new(NULL);
            // get first chain
            void *l_chain_tmp = (void*) 0x1;
            dap_chain_t *l_chain_cur = dap_chain_enum(&l_chain_tmp);
            while(l_chain_cur) {
                // only selected net
                if(l_net->pub.id.uint64 == l_chain_cur->net_id.uint64) {
                    long l_chain_datum = l_cur_datum;
                    char *l_datum_list_str = dap_db_history_addr(l_addr_base58, l_chain_cur, l_hash_out_type);
                    if(l_datum_list_str) {
                        l_cur_datum += l_chain_datum;
                        dap_string_append_printf(l_str_out, "Chain: %s\n", l_chain_cur->name);
                        dap_string_append_printf(l_str_out, "%s\n\n", l_datum_list_str);
                        DAP_DELETE(l_datum_list_str);
                    }
                }
                // next chain
                dap_chain_enum_unlock();
                l_chain_cur = dap_chain_enum(&l_chain_tmp);
            }
            dap_chain_enum_unlock();
            dap_chain_node_cli_set_reply_text(a_str_reply, l_str_out->str);
            dap_string_free(l_str_out, true);
            DAP_DELETE(l_addr_base58);
            return 0;

        }
        else{
            dap_chain_node_cli_set_reply_text(a_str_reply, "not found parameter '-all', '-wallet' or '-addr'");
            return -1;
        }
        return 0;
    }

    dap_chain_node_cli_set_reply_text(a_str_reply, "unknown command code %d", l_cmd);
    return -5;
}


