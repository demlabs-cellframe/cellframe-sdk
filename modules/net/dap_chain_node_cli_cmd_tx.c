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

#include <dap_common.h>
#include <dap_strfuncs.h>
#include <dap_string.h>
#include <dap_list.h>
#include <dap_hash.h>

#include "dap_chain_datum_tx_items.h"

#include "dap_chain_node_cli_cmd_tx.h"

#define LOG_TAG "chain_node_cli_cmd_tx"

#include "uthash.h"
// for dap_db_history_filter()
typedef struct dap_tx_data {
    dap_chain_hash_fast_t tx_hash;
    char tx_hash_str[70];
    char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    //size_t obj_num;
    size_t pos_num;
    dap_chain_datum_t *datum;
    dap_chain_addr_t addr;
    bool is_use_all_cur_out;// find cur addr in prev OUT items
    UT_hash_handle hh;
} dap_tx_data_t;

/*static char* dap_db_new_history_timestamp()
{
    static pthread_mutex_t s_mutex = PTHREAD_MUTEX_INITIALIZER;
    // get unique key
    pthread_mutex_lock(&s_mutex);
    static time_t s_last_time = 0;
    static uint64_t s_suffix = 0;
    time_t l_cur_time = time(NULL);
    if(s_last_time == l_cur_time)
        s_suffix++;
    else {
        s_suffix = 0;
        s_last_time = l_cur_time;
    }
    char *l_str = dap_strdup_printf("%lld_%lld", (uint64_t) l_cur_time, s_suffix);
    pthread_mutex_unlock(&s_mutex);
    return l_str;
}*/

// for dap_db_history_tx & dap_db_history_addr()
static dap_chain_datum_t* get_prev_tx(dap_tx_data_t *a_tx_data)
{
    if(!a_tx_data)
        return NULL;
    dap_chain_datum_t *l_datum = a_tx_data->datum;
    return l_datum;
}

/**
 * Get data according the history log
 *
 * return history string
 */
char* dap_db_history_tx(dap_chain_hash_fast_t* a_tx_hash, dap_chain_t * a_chain)
{
    dap_string_t *l_str_out = dap_string_new(NULL);

    bool l_tx_hash_found = false;
    dap_tx_data_t *l_tx_data_hash = NULL;
    // load transactions
    dap_chain_atom_iter_t *l_atom_iter = a_chain->callback_atom_iter_create(a_chain);
    dap_chain_atom_ptr_t *l_atom = a_chain->callback_atom_iter_get_first(l_atom_iter);
    size_t l_atom_size = a_chain->callback_atom_get_size(l_atom);

    while(l_atom && l_atom_size) {
        dap_chain_datum_t *l_datum = (dap_chain_datum_t*) l_atom;
        if(!l_datum && l_datum->header.type_id != DAP_CHAIN_DATUM_TX) {
            // go to next transaction
            l_atom = a_chain->callback_atom_iter_get_next(l_atom_iter);
            l_atom_size = a_chain->callback_atom_get_size(l_atom);
            continue;
        }
        dap_tx_data_t *l_tx_data = NULL;

        // transaction
        dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t*) l_datum->data;

        // find Token items - present in emit transaction
        dap_list_t *l_list_tx_token = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_TOKEN, NULL);

        // find OUT items
        dap_list_t *l_list_out_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_OUT, NULL);
        dap_list_t *l_list_tmp = l_list_out_items;
        while(l_list_tmp) {
            const dap_chain_tx_out_t *l_tx_out = (const dap_chain_tx_out_t*) l_list_tmp->data;
            // save OUT item l_tx_out - only for first OUT item
            if(!l_tx_data)
            {
                // save tx hash
                l_tx_data = DAP_NEW_Z(dap_tx_data_t);
                dap_chain_hash_fast_t l_tx_hash;
                dap_hash_fast(l_tx, dap_chain_datum_tx_get_size(l_tx), &l_tx_hash);
                memcpy(&l_tx_data->tx_hash, &l_tx_hash, sizeof(dap_chain_hash_fast_t));
                memcpy(&l_tx_data->addr, &l_tx_out->addr, sizeof(dap_chain_addr_t));
                dap_chain_hash_fast_to_str(&l_tx_data->tx_hash, l_tx_data->tx_hash_str,
                        sizeof(l_tx_data->tx_hash_str));
                //l_tx_data->pos_num = l_count;
                //l_tx_data->datum = l_datum;
                l_tx_data->datum = DAP_NEW_SIZE(dap_chain_datum_t, l_atom_size);
                memcpy(l_tx_data->datum, l_datum, l_atom_size);
                // save token name
                if(l_list_tx_token) {
                    dap_chain_tx_token_t *tk = l_list_tx_token->data;
                    memcpy(l_tx_data->token_ticker, tk->header.ticker, sizeof(l_tx_data->token_ticker));
                }
                // take token from prev out item
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
            l_atom = a_chain->callback_atom_iter_get_next(l_atom_iter);
            l_atom_size = a_chain->callback_atom_get_size(l_atom);
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
        l_list_out_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_OUT, NULL);
        l_list_tmp = l_list_out_items;
        while(l_list_tmp) {
            const dap_chain_tx_out_t *l_tx_out = (const dap_chain_tx_out_t*) l_list_tmp->data;
            dap_tx_data_t *l_tx_data_prev = NULL;

            const char *l_token_str = NULL;
            if(l_tx_data)
                l_token_str = l_tx_data->token_ticker;
            char *l_dst_to_str =
                    (l_tx_out) ? dap_chain_addr_to_str(&l_tx_out->addr) :
                    NULL;
            dap_string_append_printf(l_str_out, " OUT item %lld %s to %s\n",
                    l_tx_out->header.value,
                    dap_strlen(l_token_str) > 0 ? l_token_str : "?",
                    l_dst_to_str ? l_dst_to_str : "?"
                                   );
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
            if(!dap_hash_fast_is_blank(&tx_prev_hash))
                dap_chain_hash_fast_to_str(&tx_prev_hash, l_tx_hash_str, sizeof(l_tx_hash_str));
            else
                strcpy(l_tx_hash_str, "Null");
            dap_string_append_printf(l_str_out, " IN item \n  prev tx_hash %s\n", l_tx_hash_str);

            //find prev OUT item
            dap_tx_data_t *l_tx_data_prev = NULL;
            HASH_FIND(hh, l_tx_data_hash, &tx_prev_hash, sizeof(dap_chain_hash_fast_t), l_tx_data_prev);
            if(l_tx_data_prev != NULL) {

                dap_chain_datum_t *l_datum_prev = get_prev_tx(l_tx_data_prev);
                dap_chain_datum_tx_t *l_tx_prev =
                        l_datum_prev ? (dap_chain_datum_tx_t*) l_datum_prev->data : NULL;

                // find OUT items in prev datum
                dap_list_t *l_list_out_prev_items = dap_chain_datum_tx_items_get(l_tx_prev,
                        TX_ITEM_TYPE_OUT, NULL);
                // find OUT item for IN item;
                dap_list_t *l_list_out_prev_item = dap_list_nth(l_list_out_prev_items,
                        l_tx_in->header.tx_out_prev_idx);
                dap_chain_tx_out_t *l_tx_prev_out =
                        l_list_out_prev_item ?
                                               (dap_chain_tx_out_t*) l_list_out_prev_item->data :
                                               NULL;
                // print value from prev out item
                dap_string_append_printf(l_str_out, "  prev OUT item value=%lld",
                        l_tx_prev_out ? l_tx_prev_out->header.value : 0);
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

    // if no history
    if(!l_str_out->len)
        dap_string_append(l_str_out, "empty");
    char *l_ret_str = l_str_out ? dap_string_free(l_str_out, false) : NULL;
    return l_ret_str;
}

/**
 * Get data according the history log
 *
 * return history string
 */
char* dap_db_history_addr(dap_chain_addr_t * a_addr, dap_chain_t * a_chain)
{
    dap_string_t *l_str_out = dap_string_new(NULL);

    dap_tx_data_t *l_tx_data_hash = NULL;
    // load transactions
    dap_chain_atom_iter_t *l_atom_iter = a_chain->callback_atom_iter_create(a_chain);
    dap_chain_atom_ptr_t *l_atom = a_chain->callback_atom_iter_get_first(l_atom_iter);
    if (!l_atom) {
        return NULL;
    }
    size_t l_atom_size = a_chain->callback_atom_get_size(l_atom);

    while(l_atom && l_atom_size) {
        dap_chain_datum_t *l_datum = a_chain->callback_atom_get_datum ? a_chain->callback_atom_get_datum(l_atom) : (dap_chain_datum_t*)l_atom;
        if(!l_datum || l_datum->header.type_id != DAP_CHAIN_DATUM_TX) {
            // go to next transaction
            l_atom = a_chain->callback_atom_iter_get_next(l_atom_iter);
            l_atom_size = a_chain->callback_atom_get_size(l_atom);
            continue;
        }
        // transaction
        dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t*) l_datum->data;
        dap_list_t *l_records_out = NULL;
        // transaction time
        char *l_time_str = NULL;
        {
            if(l_tx->header.ts_created > 0) {
                time_t rawtime = (time_t) l_tx->header.ts_created;
                struct tm * timeinfo;
                timeinfo = localtime(&rawtime);
                if(timeinfo)
                    l_time_str = dap_strdup(asctime(timeinfo));
            }
            else
                l_time_str = dap_strdup(" ");
        }

        // find Token items - present in emit transaction
        dap_list_t *l_list_tx_token = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_TOKEN, NULL);

        // list of dap_tx_data_t*; info about OUT item in current transaction
        dap_list_t *l_list_out_info = NULL;

        // find OUT items
        dap_list_t *l_list_out_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_OUT, NULL);
        dap_list_t *l_list_out_items_tmp = l_list_out_items;
        while(l_list_out_items_tmp) {
            const dap_chain_tx_out_t *l_tx_out = (const dap_chain_tx_out_t*) l_list_out_items_tmp->data;
            // save OUT item l_tx_out
            {
                // save tx hash
                // info about OUT item in current transaction
                dap_tx_data_t *l_tx_data = DAP_NEW_Z(dap_tx_data_t);
                dap_chain_hash_fast_t l_tx_hash;
                dap_hash_fast(l_tx, dap_chain_datum_tx_get_size(l_tx), &l_tx_hash);
                memcpy(&l_tx_data->tx_hash, &l_tx_hash, sizeof(dap_chain_hash_fast_t));
                memcpy(&l_tx_data->addr, &l_tx_out->addr, sizeof(dap_chain_addr_t));
                dap_chain_hash_fast_to_str(&l_tx_data->tx_hash, l_tx_data->tx_hash_str, sizeof(l_tx_data->tx_hash_str));
                l_tx_data->datum = DAP_NEW_SIZE(dap_chain_datum_t, l_atom_size);
                memcpy(l_tx_data->datum, l_datum, l_atom_size);
                // save token name
                if(l_tx_data && l_list_tx_token) {
                    dap_chain_tx_token_t *tk = l_list_tx_token->data;
                    memcpy(l_tx_data->token_ticker, tk->header.ticker, sizeof(l_tx_data->token_ticker));
                }
                HASH_ADD(hh, l_tx_data_hash, tx_hash, sizeof(dap_chain_hash_fast_t), l_tx_data);

                // save OUT items to list
                l_records_out = dap_list_append(l_records_out, (void*) l_tx_out);
                // save info about OUT items to list
                l_list_out_info = dap_list_append(l_list_out_info, (void*) l_tx_data);
            }
            l_list_out_items_tmp = dap_list_next(l_list_out_items_tmp);
        }

        // find IN items
        dap_list_t *l_list_in_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_IN, NULL);
        dap_list_t *l_list_in_items_tmp = l_list_in_items;
        // find cur addr in prev OUT items
        //bool l_is_use_all_cur_out = false;
        {
            while(l_list_in_items_tmp) {
                const dap_chain_tx_in_t *l_tx_in = (const dap_chain_tx_in_t*) l_list_in_items_tmp->data;
                dap_chain_hash_fast_t tx_prev_hash = l_tx_in->header.tx_prev_hash;

                //find prev OUT item
                dap_tx_data_t *l_tx_data_prev = NULL;
                HASH_FIND(hh, l_tx_data_hash, &tx_prev_hash, sizeof(dap_chain_hash_fast_t), l_tx_data_prev);
                if(l_tx_data_prev != NULL) {
                    // fill token in all l_tx_data from prev transaction

                    dap_list_t *l_list_out_info_tmp = l_list_out_info;
                    while(l_list_out_info_tmp) {
                        dap_tx_data_t *l_tx_data = (dap_tx_data_t*) l_list_out_info_tmp->data;
                        if(l_tx_data) {
                            // get token from prev tx
                            memcpy(l_tx_data->token_ticker, l_tx_data_prev->token_ticker,
                                    sizeof(l_tx_data->token_ticker));
                            dap_chain_datum_t *l_datum_prev = get_prev_tx(l_tx_data_prev);
                            dap_chain_datum_tx_t *l_tx_prev =
                                    l_datum_prev ? (dap_chain_datum_tx_t*) l_datum_prev->data : NULL;

                            // find OUT items in prev datum
                            dap_list_t *l_list_out_prev_items = dap_chain_datum_tx_items_get(l_tx_prev,
                                    TX_ITEM_TYPE_OUT, NULL);
                            // find OUT item for IN item;
                            dap_list_t *l_list_out_prev_item = dap_list_nth(l_list_out_prev_items,
                                    l_tx_in->header.tx_out_prev_idx);
                            dap_chain_tx_out_t *l_tx_prev_out =
                                    l_list_out_prev_item ?
                                                           (dap_chain_tx_out_t*) l_list_out_prev_item->data :
                                                           NULL;
                            if(l_tx_prev_out && !memcmp(&l_tx_prev_out->addr, a_addr, sizeof(dap_chain_addr_t)))
                                l_tx_data->is_use_all_cur_out = true;

                        }
                        l_list_out_info_tmp = dap_list_next(l_list_out_info_tmp);
                    }
                }
                l_list_in_items_tmp = dap_list_next(l_list_in_items_tmp);
            }
            // find prev OUT items for IN items
            dap_list_t *l_list_in_items2_tmp = l_list_in_items; // go to begin of list
            while(l_list_in_items2_tmp) {
                const dap_chain_tx_in_t *l_tx_in = (const dap_chain_tx_in_t*) l_list_in_items2_tmp->data;
                dap_chain_hash_fast_t tx_prev_hash = l_tx_in->header.tx_prev_hash;
                // if first transaction - empty prev OUT item
                if(dap_hash_fast_is_blank(&tx_prev_hash)) {

                    dap_tx_data_t *l_tx_data = NULL;
                    dap_list_t *l_list_out_info_tmp = l_list_out_info;
                    while(l_list_out_info_tmp) {
                        l_tx_data = (dap_tx_data_t*) l_list_out_info_tmp->data;
                        if(l_tx_data->token_ticker[0])
                            break;
                        l_list_out_info_tmp = dap_list_next(l_list_out_info_tmp);
                    }

                    // add emit info to ret string
                    if(l_tx_data && !memcmp(&l_tx_data->addr, a_addr, sizeof(dap_chain_addr_t))) {
                        dap_list_t *l_records_tmp = l_records_out;
                        while(l_records_tmp) {

                            const dap_chain_tx_out_t *l_tx_out = (const dap_chain_tx_out_t*) l_records_tmp->data;
                            dap_string_append_printf(l_str_out, "tx hash %s \n emit %lu %s\n",
                                    l_tx_data->tx_hash_str,
                                    l_tx_out->header.value,
                                    l_tx_data->token_ticker);
                            l_records_tmp = dap_list_next(l_records_tmp);
                        }
                    }
                    //dap_list_free(l_records_out);
                }
                // in other transactions except first one
                else {
                    //find prev OUT item
                    dap_tx_data_t *l_tx_data_prev = NULL;
                    HASH_FIND(hh, l_tx_data_hash, &tx_prev_hash, sizeof(dap_chain_hash_fast_t), l_tx_data_prev);
                    if(l_tx_data_prev != NULL) {
                        char *l_src_str = NULL;
                        bool l_src_str_is_cur = false;

                        dap_tx_data_t *l_tx_data = NULL;
                        dap_list_t *l_list_out_info_tmp = l_list_out_info;
                        while(l_list_out_info_tmp) {
                            l_tx_data = (dap_tx_data_t*) l_list_out_info_tmp->data;
                            if(l_tx_data->token_ticker[0])
                                break;
                            l_list_out_info_tmp = dap_list_next(l_list_out_info_tmp);
                        }
                        if(l_tx_data) {
                            // get token from prev tx
                            memcpy(l_tx_data->token_ticker, l_tx_data_prev->token_ticker,
                                    sizeof(l_tx_data->token_ticker));

                            dap_chain_datum_t *l_datum_prev = get_prev_tx(l_tx_data_prev);
                            dap_chain_datum_tx_t *l_tx_prev =
                                    l_datum_prev ? (dap_chain_datum_tx_t*) l_datum_prev->data : NULL;

                            // find OUT items in prev datum
                            dap_list_t *l_list_out_prev_items = dap_chain_datum_tx_items_get(l_tx_prev,
                                    TX_ITEM_TYPE_OUT, NULL);
                            // find OUT item for IN item;
                            dap_list_t *l_list_out_prev_item = dap_list_nth(l_list_out_prev_items,
                                    l_tx_in->header.tx_out_prev_idx);
                            dap_chain_tx_out_t *l_tx_prev_out =
                                    l_list_out_prev_item ?
                                                           (dap_chain_tx_out_t*) l_list_out_prev_item->data :
                                                           NULL;
                            // if use src addr
                            bool l_is_use_src_addr = false;
                            // find source addrs
                            dap_string_t *l_src_addr = dap_string_new(NULL);
                            {
                                // find IN items in prev datum - for get destination addr
                                dap_list_t *l_list_in_prev_items = dap_chain_datum_tx_items_get(l_tx_prev,
                                        TX_ITEM_TYPE_IN, NULL);
                                dap_list_t *l_list_tmp = l_list_in_prev_items;
                                while(l_list_tmp) {
                                    dap_chain_tx_in_t *l_tx_prev_in = l_list_tmp->data;
                                    dap_chain_hash_fast_t l_tx_prev_prev_hash =
                                            l_tx_prev_in->header.tx_prev_hash;
                                    //find prev OUT item
                                    dap_tx_data_t *l_tx_data_prev_prev = NULL;
                                    HASH_FIND(hh, l_tx_data_hash, &l_tx_prev_prev_hash,
                                            sizeof(dap_chain_hash_fast_t), l_tx_data_prev_prev);
                                    if(l_tx_data_prev_prev) {
                                        // if use src addr
                                        if(l_tx_data_prev_prev &&
                                                !memcmp(&l_tx_data_prev_prev->addr, a_addr,
                                                        sizeof(dap_chain_addr_t)))
                                            l_is_use_src_addr = true;
                                        char *l_str = dap_chain_addr_to_str(&l_tx_data_prev_prev->addr);
                                        if(l_src_addr->len > 0)
                                            dap_string_append_printf(l_src_addr, "\n   %s", l_str);
                                        else
                                            dap_string_append_printf(l_src_addr, "%s", l_str); // first record
                                        DAP_DELETE(l_str);
                                    }
                                    l_list_tmp = dap_list_next(l_list_tmp);
                                }
                            }

                            char *l_dst_to_str =
                                    (l_tx_prev_out) ? dap_chain_addr_to_str(&l_tx_prev_out->addr) :
                                    NULL;
                            // if use dst addr
                            bool l_is_use_dst_addr = false;
                            if(!memcmp(&l_tx_prev_out->addr, a_addr, sizeof(dap_chain_addr_t)))
                                l_is_use_dst_addr = true;

                            l_src_str_is_cur = l_is_use_src_addr;
                            if(l_src_addr->len <= 1) {
                                l_src_str =
                                        (l_tx_data) ? dap_chain_addr_to_str(&l_tx_data->addr) :
                                        NULL;
                                if(!memcmp(&l_tx_prev_out->addr, a_addr, sizeof(dap_chain_addr_t)))
                                    l_src_str_is_cur = true;
                                dap_string_free(l_src_addr, true);
                            }
                            else
                                l_src_str = dap_string_free(l_src_addr, false);
                            if(l_is_use_src_addr && !l_is_use_dst_addr) {
                                dap_string_append_printf(l_str_out,
                                        "tx hash %s \n %s in send  %lu %s from %s\n to %s\n",
                                        l_tx_data->tx_hash_str,
                                        l_time_str ? l_time_str : "",
                                        l_tx_prev_out->header.value,
                                        l_tx_data->token_ticker,
                                        l_src_str ? l_src_str : "",
                                        l_dst_to_str);
                            } else if(l_is_use_dst_addr && !l_is_use_src_addr) {
                                if(!l_src_str_is_cur)
                                    dap_string_append_printf(l_str_out,
                                            "tx hash %s \n %s in recv %lu %s from %s\n",
                                            l_tx_data->tx_hash_str,
                                            l_time_str ? l_time_str : "",
                                            l_tx_prev_out->header.value,
                                            l_tx_data->token_ticker,
                                            l_src_str ? l_src_str : "");
                            }

                            DAP_DELETE(l_dst_to_str);
                            dap_list_free(l_list_out_prev_items);
                        }

                        // OUT items
                        dap_list_t *l_records_tmp = l_records_out;
                        while(l_records_tmp) {

                            const dap_chain_tx_out_t *l_tx_out = (const dap_chain_tx_out_t*) l_records_tmp->data;

                            if(l_tx_data->is_use_all_cur_out
                                    || !memcmp(&l_tx_out->addr, a_addr, sizeof(dap_chain_addr_t))) {

                                char *l_addr_str = (l_tx_out) ? dap_chain_addr_to_str(&l_tx_out->addr) : NULL;

                                if(!memcmp(&l_tx_out->addr, a_addr, sizeof(dap_chain_addr_t))) {
                                    if(!l_src_str_is_cur)
                                        dap_string_append_printf(l_str_out,
                                                "tx hash %s \n %s recv %lu %s from %s\n",
                                                l_tx_data->tx_hash_str,
                                                l_time_str ? l_time_str : "",
                                                l_tx_out->header.value,
                                                l_tx_data_prev->token_ticker,
                                                l_src_str ? l_src_str : "?");
                                    // break search prev OUT items for IN items
                                    l_list_in_items2_tmp = NULL;
                                }
                                else {
                                    dap_string_append_printf(l_str_out,
                                            "tx hash %s \n %s send %lu %s to %s\n",
                                            l_tx_data->tx_hash_str,
                                            l_time_str ? l_time_str : "",
                                            l_tx_out->header.value,
                                            l_tx_data_prev->token_ticker,
                                            l_addr_str ? l_addr_str : "");
                                    l_list_in_items2_tmp = NULL;
                                }
                                DAP_DELETE(l_addr_str);
                            }

                            l_records_tmp = dap_list_next(l_records_tmp);
                        }
                        //dap_list_free(l_records_out);
                        DAP_DELETE(l_src_str);

                    }
                }
                l_list_in_items2_tmp = dap_list_next(l_list_in_items2_tmp);
            }
//                l_list_in_items_tmp = dap_list_next(l_list_in_items_tmp);
//            }
        }

        if(l_list_tx_token)
            dap_list_free(l_list_tx_token);
        if(l_list_out_items)
            dap_list_free(l_list_out_items);
        if(l_list_in_items)
            dap_list_free(l_list_in_items);
        dap_list_free(l_records_out);
        dap_list_free(l_list_out_info);
        DAP_DELETE(l_time_str);

        // go to next transaction
        l_atom = a_chain->callback_atom_iter_get_next(l_atom_iter);
        l_atom_size = l_atom ? a_chain->callback_atom_get_size(l_atom) : 0;
    }

    // delete hashes
    dap_tx_data_t *l_iter_current, *l_item_tmp;
    HASH_ITER(hh, l_tx_data_hash , l_iter_current, l_item_tmp)
    {
        // delete datum
        DAP_DELETE(l_iter_current->datum);
        // delete struct
        DAP_DELETE(l_iter_current);
        HASH_DEL(l_tx_data_hash, l_iter_current);
    }
    // if no history
    if(!l_str_out->len)
        dap_string_append(l_str_out, " empty");
    char *l_ret_str = l_str_out ? dap_string_free(l_str_out, false) : NULL;
    return l_ret_str;
}
