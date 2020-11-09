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

#include "dap_common.h"
#include "dap_enc_base58.h"
#include "dap_strfuncs.h"
#include "dap_string.h"
#include "dap_list.h"
#include "dap_hash.h"

#include "dap_chain_wallet.h"
#include "dap_chain_datum.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_node_cli.h"
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
char* dap_db_history_tx(dap_chain_hash_fast_t* a_tx_hash, dap_chain_t * a_chain, const char *a_hash_out_type)
{
    dap_string_t *l_str_out = dap_string_new(NULL);

    bool l_tx_hash_found = false;
    dap_tx_data_t *l_tx_data_hash = NULL;
    // load transactions
    dap_chain_atom_iter_t *l_atom_iter = a_chain->callback_atom_iter_create(a_chain);
    size_t l_atom_size = 0;
    dap_chain_atom_ptr_t *l_atom = a_chain->callback_atom_iter_get_first(l_atom_iter, &l_atom_size);

    while(l_atom && l_atom_size) {
        dap_chain_datum_t *l_datum = (dap_chain_datum_t*) l_atom;
        if(!l_datum && l_datum->header.type_id != DAP_CHAIN_DATUM_TX) {
            // go to next transaction
            l_atom = a_chain->callback_atom_iter_get_next(l_atom_iter, &l_atom_size);
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
        l_list_out_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_OUT, NULL);
        l_list_tmp = l_list_out_items;
        while(l_list_tmp) {
            const dap_chain_tx_out_t *l_tx_out = (const dap_chain_tx_out_t*) l_list_tmp->data;
            //dap_tx_data_t *l_tx_data_prev = NULL;

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
char* dap_db_history_addr(dap_chain_addr_t * a_addr, dap_chain_t * a_chain, const char *a_hash_out_type)
{
    dap_string_t *l_str_out = dap_string_new(NULL);

    dap_tx_data_t *l_tx_data_hash = NULL;
    // load transactions
    dap_chain_atom_iter_t *l_atom_iter = a_chain->callback_atom_iter_create(a_chain);
    size_t l_atom_size=0;
    dap_chain_atom_ptr_t *l_atom = a_chain->callback_atom_iter_get_first(l_atom_iter, &l_atom_size);
    if (!l_atom) {
        return NULL;
    }

    while(l_atom && l_atom_size) {
        size_t l_datums_count =0;
        dap_chain_datum_t **l_datums = a_chain->callback_atom_get_datums ? a_chain->callback_atom_get_datums(l_atom, l_atom_size, &l_datums_count) :
                                                                          NULL;
        if (! l_datums){
            log_it(L_WARNING,"Not defined callback_atom_get_datums for chain \"%s\"", a_chain->name);
            break;
        }

        for (size_t d=0; d< l_datums_count; d++){
            dap_chain_datum_t *l_datum = l_datums && l_datums_count ? l_datums[d] :NULL;
            if(!l_datum || l_datum->header.type_id != DAP_CHAIN_DATUM_TX) {
                // go to next transaction
                l_atom = a_chain->callback_atom_iter_get_next(l_atom_iter, &l_atom_size);
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
                                char *tx_hash_str;
                                if(!dap_strcmp(a_hash_out_type,"hex"))
                                    tx_hash_str = dap_strdup( l_tx_data->tx_hash_str);
                                else
                                    tx_hash_str = dap_enc_base58_from_hex_str_to_str( l_tx_data->tx_hash_str);
                                const dap_chain_tx_out_t *l_tx_out = (const dap_chain_tx_out_t*) l_records_tmp->data;

                                if(!dap_strcmp(a_hash_out_type,"hex")){
                                dap_string_append_printf(l_str_out, "tx hash %s \n emit %lu %s\n",
                                        tx_hash_str,//l_tx_data->tx_hash_str,
                                        l_tx_out->header.value,
                                        l_tx_data->token_ticker);
                                }
                                else {
                                    dap_string_append_printf(l_str_out, "tx hash %s \n emit %lu %s\n",
                                            l_tx_data->tx_hash_str,
                                            l_tx_out->header.value,
                                            l_tx_data->token_ticker);
                                }
                                DAP_DELETE(tx_hash_str);
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

                                l_src_str_is_cur = l_is_use_src_addr;
                                if(l_src_addr->len <= 1) {
                                    l_src_str =
                                            (l_tx_data) ? dap_chain_addr_to_str(&l_tx_data->addr) :
                                            NULL;
                                    if(l_tx_prev_out && !memcmp(&l_tx_prev_out->addr, a_addr, sizeof(dap_chain_addr_t)))
                                        l_src_str_is_cur = true;
                                    dap_string_free(l_src_addr, true);
                                }
                                else
                                    l_src_str = dap_string_free(l_src_addr, false);

                                if(l_tx_prev_out) {
                                    char *l_dst_to_str = dap_chain_addr_to_str(&l_tx_prev_out->addr);
                                    // if use dst addr
                                    bool l_is_use_dst_addr = false;
                                    if(!memcmp(&l_tx_prev_out->addr, a_addr, sizeof(dap_chain_addr_t)))
                                        l_is_use_dst_addr = true;
                                    char *tx_hash_str;
                                    if(!dap_strcmp(a_hash_out_type, "hex"))
                                        tx_hash_str = dap_strdup(l_tx_data->tx_hash_str);
                                    else
                                        tx_hash_str = dap_enc_base58_from_hex_str_to_str(l_tx_data->tx_hash_str);
                                    if(l_is_use_src_addr && !l_is_use_dst_addr) {
                                        dap_string_append_printf(l_str_out,
                                                "tx hash %s \n %s in send  %lu %s from %s\n to %s\n",
                                                tx_hash_str,//l_tx_data->tx_hash_str,
                                                l_time_str ? l_time_str : "",
                                                l_tx_prev_out->header.value,
                                                l_tx_data->token_ticker,
                                                l_src_str ? l_src_str : "",
                                                l_dst_to_str);
                                    } else if(l_is_use_dst_addr && !l_is_use_src_addr) {
                                        if(!l_src_str_is_cur)
                                            dap_string_append_printf(l_str_out,
                                                    "tx hash %s \n %s in recv %lu %s from %s\n",
                                                    tx_hash_str,//l_tx_data->tx_hash_str,
                                                    l_time_str ? l_time_str : "",
                                                    l_tx_prev_out->header.value,
                                                    l_tx_data->token_ticker,
                                                    l_src_str ? l_src_str : "");
                                    }
                                    DAP_DELETE(tx_hash_str);
                                    DAP_DELETE(l_dst_to_str);
                                }
                                dap_list_free(l_list_out_prev_items);
                            }

                            // OUT items
                            dap_list_t *l_records_tmp = l_records_out;
                            while(l_records_tmp) {

                                const dap_chain_tx_out_t *l_tx_out = (const dap_chain_tx_out_t*) l_records_tmp->data;

                                if(l_tx_data->is_use_all_cur_out
                                        || !memcmp(&l_tx_out->addr, a_addr, sizeof(dap_chain_addr_t))) {

                                    char *l_addr_str = (l_tx_out) ? dap_chain_addr_to_str(&l_tx_out->addr) : NULL;

                                    char *tx_hash_str;
                                    if(!dap_strcmp(a_hash_out_type, "hex"))
                                        tx_hash_str = dap_strdup(l_tx_data->tx_hash_str);
                                    else
                                        tx_hash_str = dap_enc_base58_from_hex_str_to_str(l_tx_data->tx_hash_str);
                                    if(!memcmp(&l_tx_out->addr, a_addr, sizeof(dap_chain_addr_t))) {
                                        if(!l_src_str_is_cur)
                                            dap_string_append_printf(l_str_out,
                                                    "tx hash %s \n %s recv %lu %s from %s\n",
                                                    tx_hash_str,//l_tx_data->tx_hash_str,
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
                                                tx_hash_str,//l_tx_data->tx_hash_str,
                                                l_time_str ? l_time_str : "",
                                                l_tx_out->header.value,
                                                l_tx_data_prev->token_ticker,
                                                l_addr_str ? l_addr_str : "");
                                        l_list_in_items2_tmp = NULL;
                                    }
                                    DAP_DELETE(tx_hash_str);
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
            l_atom = a_chain->callback_atom_iter_get_next(l_atom_iter, &l_atom_size);
        }
        DAP_DELETE(l_datums);
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

static char* dap_db_history_token_list(dap_chain_t * a_chain, const char *a_token_name, const char *a_hash_out_type, size_t *a_token_num)
{
    dap_string_t *l_str_out = dap_string_new(NULL);
    *a_token_num  = 0;
    bool l_tx_hash_found = false;
    // list all transactions
    dap_tx_data_t *l_tx_data_hash = NULL;
    // load transactions
    dap_chain_atom_iter_t *l_atom_iter = a_chain->callback_atom_iter_create(a_chain);
    dap_chain_atom_ptr_t *l_atom = a_chain->callback_atom_iter_get_first(l_atom_iter);
    size_t l_atom_size = a_chain->callback_atom_get_size(l_atom);
    while(l_atom && l_atom_size) {
        dap_chain_datum_t *l_datum =
                a_chain->callback_atom_get_datum ?
                        a_chain->callback_atom_get_datum(l_atom) : (dap_chain_datum_t*) l_atom;
        if(!l_datum) {
            // go to next transaction
            l_atom = a_chain->callback_atom_iter_get_next(l_atom_iter);
            l_atom_size = a_chain->callback_atom_get_size(l_atom);
            log_it(L_ERROR, "datum=NULL for atom=0x%x", l_atom);
            continue;
        }
        char l_time_str[70];
        // get time of create datum
        if(dap_time_to_str_rfc822(l_time_str, 71, l_datum->header.ts_create) < 1)
            l_time_str[0] = '\0';
        if(l_datum->header.type_id==DAP_CHAIN_DATUM_TOKEN_DECL) {
            dap_chain_datum_token_t *l_token = (dap_chain_datum_token_t*) l_datum->data;
            if(!a_token_name || !dap_strcmp(l_token->ticker, a_token_name)) {
                dap_string_append_printf(l_str_out, "token %s, created: %s\n", l_token->ticker, l_time_str);
                switch (l_token->type) {
                // Simple private token decl
                case DAP_CHAIN_DATUM_TOKEN_TYPE_SIMPLE:
                    dap_string_append_printf(l_str_out, "  total_supply: %.0llf(%llu), signs: valid/total %02d/%02d \n",
                            l_token->header_private.total_supply / DATOSHI_LD,
                            l_token->header_private.total_supply,
                            l_token->header_private.signs_valid, l_token->header_private.signs_total);
                    break;
                case DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_DECL:
                    dap_string_append_printf(l_str_out, "  tsd_total_size: %llu, flags: 0x%x \n",
                            l_token->header_private_decl.tsd_total_size,
                            l_token->header_private_decl.flags);
                    break;
                case DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_UPDATE:
                    dap_string_append_printf(l_str_out, "  tsd_total_size: %llu, padding: 0x%x \n",
                            l_token->header_private_update.tsd_total_size,
                            l_token->header_private_update.padding);
                    break;
                case DAP_CHAIN_DATUM_TOKEN_TYPE_PUBLIC: {
                    char *l_addr = dap_chain_addr_to_str(&l_token->header_public.premine_address);
                    dap_string_append_printf(l_str_out,
                            " total_supply: %.0llf(%llu), flags: 0x%x\n, premine_supply: %llu, premine_address '%s'\n",
                            l_token->header_public.total_supply / DATOSHI_LD,
                            l_token->header_public.total_supply,
                            l_token->header_public.flags,
                            l_token->header_public.premine_supply,
                            l_addr ? l_addr : "-");
                    DAP_DELETE(l_addr);
                }
                    break;
                default:
                    dap_string_append_printf(l_str_out, "unknown token type: 0x%x\n", l_token->type);
                    break;

                }
                dap_string_append_printf(l_str_out, "\n");
                (*a_token_num)++;
            }
        }

        // go to next transaction
        l_atom = a_chain->callback_atom_iter_get_next(l_atom_iter);
        l_atom_size = a_chain->callback_atom_get_size(l_atom);
    }

    a_chain->callback_atom_iter_delete(l_atom_iter);
    char *l_ret_str = l_str_out ? dap_string_free(l_str_out, false) : NULL;
    return l_ret_str;
}

/**
 * Get data according the history log
 *
 * return history string
 */
static char* dap_db_history_filter(dap_chain_t * a_chain, const char *a_token_name, const char *a_hash_out_type)
{
    dap_string_t *l_str_out = dap_string_new(NULL);

    bool l_tx_hash_found = false;
    // list all transactions
    dap_tx_data_t *l_tx_data_hash = NULL;
    // load transactions
    dap_chain_atom_iter_t *l_atom_iter = a_chain->callback_atom_iter_create(a_chain);
    dap_chain_atom_ptr_t *l_atom = a_chain->callback_atom_iter_get_first(l_atom_iter);
    size_t l_atom_size = a_chain->callback_atom_get_size(l_atom);
    size_t l_datum_num = 0, l_token_num = 0, l_emission_num = 0, l_tx_num = 0;
    while(l_atom && l_atom_size) {
        dap_chain_datum_t *l_datum =
                a_chain->callback_atom_get_datum ?
                        a_chain->callback_atom_get_datum(l_atom) : (dap_chain_datum_t*) l_atom;
        if(!l_datum) {
            // go to next transaction
            l_atom = a_chain->callback_atom_iter_get_next(l_atom_iter);
            l_atom_size = a_chain->callback_atom_get_size(l_atom);
            log_it(L_ERROR, "datum=NULL for atom=0x%x", l_atom);
            continue;
        }
        char l_time_str[70];
        // get time of create datum
        if(dap_time_to_str_rfc822(l_time_str, 71, l_datum->header.ts_create) < 1)
            l_time_str[0] = '\0';
        switch (l_datum->header.type_id) {

        // token
        case DAP_CHAIN_DATUM_TOKEN_DECL: {
            dap_chain_datum_token_t *l_token = (dap_chain_datum_token_t*) l_datum->data;
            if(!a_token_name || !dap_strcmp(l_token->ticker, a_token_name)) {
                dap_string_append_printf(l_str_out, "token %s, created: %s\n", l_token->ticker, l_time_str);
                switch (l_token->type) {
                // Simple private token decl
                case DAP_CHAIN_DATUM_TOKEN_TYPE_SIMPLE:
                    dap_string_append_printf(l_str_out, "  total_supply: %.0llf(%llu), signs: valid/total %02d/%02d \n",
                            l_token->header_private.total_supply / DATOSHI_LD,
                            l_token->header_private.total_supply,
                            l_token->header_private.signs_valid, l_token->header_private.signs_total);
                    break;
                case DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_DECL:
                    dap_string_append_printf(l_str_out, "  tsd_total_size: %llu, flags: 0x%x \n",
                            l_token->header_private_decl.tsd_total_size,
                            l_token->header_private_decl.flags);
                    break;
                case DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_UPDATE:
                    dap_string_append_printf(l_str_out, "  tsd_total_size: %llu, padding: 0x%x \n",
                            l_token->header_private_update.tsd_total_size,
                            l_token->header_private_update.padding);
                    break;
                case DAP_CHAIN_DATUM_TOKEN_TYPE_PUBLIC: {
                    char *l_addr = dap_chain_addr_to_str(&l_token->header_public.premine_address);
                    dap_string_append_printf(l_str_out,
                            " total_supply: %.0llf(%llu), flags: 0x%x\n, premine_supply: %llu, premine_address '%s'\n",
                            l_token->header_public.total_supply / DATOSHI_LD,
                            l_token->header_public.total_supply,
                            l_token->header_public.flags,
                            l_token->header_public.premine_supply,
                            l_addr ? l_addr : "-");
                    DAP_DELETE(l_addr);
                }
                    break;
                default:
                    dap_string_append_printf(l_str_out, "unknown token type: 0x%x\n", l_token->type);
                    break;

                }
                dap_string_append_printf(l_str_out, "\n");
                l_token_num++;
            }
        }
            break;

            // emission
        case DAP_CHAIN_DATUM_TOKEN_EMISSION: {
            dap_chain_datum_token_emission_t *l_token_em = (dap_chain_datum_token_emission_t*) l_datum->data;
            if(!a_token_name || !dap_strcmp(l_token_em->hdr.ticker, a_token_name)) {
                dap_string_append_printf(l_str_out, "emission: %.0llf(%llu) %s, type: %s, version: %d\n",
                        l_token_em->hdr.value / DATOSHI_LD, l_token_em->hdr.value, l_token_em->hdr.ticker,
                        c_dap_chain_datum_token_emission_type_str[l_token_em->hdr.type],
                        l_token_em->hdr.version);
                char * l_token_emission_address_str = dap_chain_addr_to_str(&(l_token_em->hdr.address));
                dap_string_append_printf(l_str_out, "  to addr: %s\n", l_token_emission_address_str);
                DAP_DELETE(l_token_emission_address_str);
                switch (l_token_em->hdr.type) {
                case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_UNDEFINED:
                    break;
                case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_AUTH:
                    dap_string_append_printf(l_str_out, "  signs_count: %d\n", l_token_em->data.type_auth.signs_count);
                    break;
                case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_ALGO:
                    dap_string_append_printf(l_str_out, "  codename: %s\n", l_token_em->data.type_algo.codename);
                    break;
                case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_ATOM_OWNER:
                    dap_string_append_printf(l_str_out, " value_start: %.0llf(%llu), codename: %s\n",
                            l_token_em->data.type_atom_owner.value_start / DATOSHI_LD,
                            l_token_em->data.type_atom_owner.value_start,
                            l_token_em->data.type_atom_owner.value_change_algo_codename);
                    break;
                case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_SMART_CONTRACT: {
                    char *l_addr = dap_chain_addr_to_str(&l_token_em->data.type_presale.addr);
                    // get time of create datum
                    if(dap_time_to_str_rfc822(l_time_str, 71, l_token_em->data.type_presale.lock_time) < 1)
                        l_time_str[0] = '\0';
                    dap_string_append_printf(l_str_out, "  flags: 0x%x, lock_time: %s\n",
                            l_token_em->data.type_presale.flags, l_time_str);
                    dap_string_append_printf(l_str_out, "  addr: %s\n", l_addr);
                    DAP_DELETE(l_addr);
                }
                    break;
                }
                dap_string_append_printf(l_str_out, "\n");
                l_emission_num++;
            }
        }
            break;

            // transaction
        case DAP_CHAIN_DATUM_TX:{
            dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t*) l_datum->data;


            // find Token items - present in emit transaction
            dap_list_t *l_list_tx_token = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_TOKEN, NULL);
            // find OUT items
            dap_list_t *l_list_out_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_OUT, NULL);

            dap_tx_data_t *l_tx_data = NULL;


             // calc tx hash
             dap_chain_hash_fast_t l_tx_hash;
            dap_hash_fast(l_tx, dap_chain_datum_tx_get_size(l_tx), &l_tx_hash);
            char *tx_hash_str;
            char l_tx_hash_str[70];
            dap_chain_hash_fast_to_str(&l_tx_hash, l_tx_hash_str, 70);
            if(!dap_strcmp(a_hash_out_type, "hex"))
                tx_hash_str = dap_strdup(l_tx_hash_str);
            else
                tx_hash_str = dap_enc_base58_from_hex_str_to_str(l_tx_hash_str);

            dap_string_append_printf(l_str_out, "transaction: %s hash: %s\n", l_list_tx_token ? "(emit)" : "", tx_hash_str);
            DAP_DELETE(tx_hash_str);

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
                            HASH_FIND(hh, l_tx_data_hash, &tx_prev_hash, sizeof(dap_chain_hash_fast_t), l_tx_data_prev);
                            if(l_tx_data_prev != NULL) {
                                // fill token in l_tx_data from prev transaction
                                if(l_tx_data) {
                                    // get token from prev tx
                                    memcpy(l_tx_data->token_ticker, l_tx_data_prev->token_ticker,
                                            sizeof(l_tx_data->token_ticker));
                                    break;
                                }
                            }
                            l_list_tmp_in = dap_list_next(l_list_tmp_in);
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

            // found a_tx_hash now
            // transaction time
            if(l_tx->header.ts_created > 0) {
                time_t rawtime = (time_t) l_tx->header.ts_created;
                struct tm l_timeinfo = { 0 };
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
                char *tx_hash_base58_str = NULL;
                if(!dap_hash_fast_is_blank(&tx_prev_hash)) {
                    tx_hash_base58_str = dap_enc_base58_from_hex_str_to_str(l_tx_data->tx_hash_str);
                    dap_chain_hash_fast_to_str(&tx_prev_hash, l_tx_hash_str, sizeof(l_tx_hash_str));
                }
                else {
                    strcpy(l_tx_hash_str, "Null");
                    tx_hash_base58_str = dap_strdup("Null");
                }
                if(!dap_strcmp(a_hash_out_type, "hex"))
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
            l_tx_num++;
        }
            break;
        default:
            dap_string_append_printf(l_str_out, "unknown datum type=%d %lld %s to %s\n", l_datum->header.type_id);
            break;
        }
        // go to next transaction
        l_atom = a_chain->callback_atom_iter_get_next(l_atom_iter);
        l_atom_size = a_chain->callback_atom_get_size(l_atom);
        l_datum_num++;
/*        continue;



        //////// calc hash
         dap_chain_hash_fast_t l_tx_hash;
         dap_hash_fast(l_tx, dap_chain_datum_tx_get_size(l_tx), &l_tx_hash);
         // search tx with a_tx_hash
         if(!dap_hash_fast_compare(a_tx_hash, &l_tx_hash)) {
         // go to next transaction
         l_atom = a_chain->callback_atom_iter_get_next(l_atom_iter);
         l_atom_size = a_chain->callback_atom_get_size(l_atom);
         continue;
         }







        //break;

        // go to next transaction
        l_atom = a_chain->callback_atom_iter_get_next(l_atom_iter);
        l_atom_size = a_chain->callback_atom_get_size(l_atom);
        */

    }
    a_chain->callback_atom_iter_delete(l_atom_iter);
    //total
    dap_string_append_printf(l_str_out,
            "---------------\ntokens: %u\nemissions: %u\ntransactions: %u\ntotal datums: %u", l_token_num,
            l_emission_num, l_tx_num, l_datum_num);

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
 * ledger command
 *
 */
int com_ledger(int a_argc, char ** a_argv, void *a_arg_func, char **a_str_reply)
{
    enum { CMD_NONE, CMD_LIST, CMD_TX_HISTORY };
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
        l_hash_out_type = "base58";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "invalid parameter -H, valid values: -H <hex | base58>");
        return -1;
    }

    int l_cmd = CMD_NONE;
    if (dap_chain_node_cli_find_option_val(a_argv, 1, 2, "list", NULL))
        l_cmd = CMD_LIST;
    else if (dap_chain_node_cli_find_option_val(a_argv, 1, 2, "tx", NULL))
        l_cmd = CMD_TX_HISTORY;
    // command tx_history
    if(l_cmd == CMD_TX_HISTORY) {
        bool l_is_all = dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-all", NULL);
        dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-addr", &l_addr_base58);
        dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-w", &l_wallet_name);
        dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_str);
        dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-chain", &l_chain_str);
        dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-tx", &l_tx_hash_str);

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
        //Select chain emission
        if(!l_chain_str) { // chain may be null -> then all chain use
            //dap_chain_node_cli_set_reply_text(a_str_reply, "command requires parameter '-chain'");
            //return -4;
        } else {
            if((l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_str)) == NULL) { // Can't find such chain
                dap_chain_node_cli_set_reply_text(a_str_reply,
                        "command requires parameter '-chain' to be valid chain name in chain net %s",
                        l_net_str);
                return -5;
            }
        }
        //char *l_group_mempool = dap_chain_net_get_gdb_group_mempool(l_chain);
        //const char *l_chain_group = dap_chain_gdb_get_group(l_chain);

        dap_chain_hash_fast_t l_tx_hash;
        if(l_tx_hash_str) {
            if(dap_chain_str_to_hash_fast(l_tx_hash_str, &l_tx_hash) < 0) {
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
                    l_addr = DAP_NEW_SIZE(dap_chain_addr_t, sizeof(dap_chain_addr_t));
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
        dap_chain_t *l_chain_cur;
        void *l_chain_tmp = (void*)0x1;
        int l_num = 0;
        // only one chain
        if(l_chain)
            l_chain_cur = l_chain;
        // all chain
        else
            l_chain_cur = dap_chain_enum(&l_chain_tmp);
        while(l_chain_cur) {
            // only selected net
            if(l_net->pub.id.uint64 == l_chain_cur->net_id.uint64) {
                // separator between chains
                if(l_num>0 && !l_chain)
                    dap_string_append(l_str_ret, "---------------\n");

                char *l_str_out = NULL;
                dap_string_append_printf(l_str_ret, "chain: %s\n", l_chain_cur->name);
                if(l_is_all) {
                    // without filters
                    l_str_out = dap_db_history_filter(l_chain_cur, NULL, l_hash_out_type);
                    dap_string_append_printf(l_str_ret, "all history:\n%s\n", l_str_out ? l_str_out : " empty");
                }
                else {
                    l_str_out = l_tx_hash_str ?
                                                dap_db_history_tx(&l_tx_hash, l_chain_cur, l_hash_out_type) :
                                                dap_db_history_addr(l_addr, l_chain_cur, l_hash_out_type);

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
                l_num++;
            }
            // only one chain use
            if(l_chain)
                break;
            dap_chain_enum_unlock();
            l_chain_cur = dap_chain_enum(&l_chain_tmp);
        }
        // all chain
        if(!l_chain)
            dap_chain_enum_unlock();
        dap_chain_node_cli_set_reply_text(a_str_reply, l_str_ret->str);
        dap_string_free(l_str_ret, true);
        return 0;
    }
    else{
        dap_chain_node_cli_set_reply_text(a_str_reply, "command requires parameter 'list' or 'tx' or 'info'");
        return -1;
    }
}

/**
 * token command
 *
 */
int com_token(int a_argc, char ** a_argv, void *a_arg_func, char **a_str_reply)
{
    enum { CMD_NONE, CMD_LIST, CMD_INFO, CMD_TX };
    int arg_index = 1;
    const char *l_addr_base58 = NULL;
    const char *l_wallet_name = NULL;
    const char *l_net_str = NULL;
    const char *l_chain_str = NULL;

    dap_chain_t * l_chain = NULL;
    dap_chain_net_t * l_net = NULL;

    const char * l_hash_out_type = NULL;
    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "base58";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "invalid parameter -H, valid values: -H <hex | base58>");
        return -1;
    }

    //bool l_is_all = dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-all", NULL);
    //dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-addr", &l_addr_base58);
    //dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-w", &l_wallet_name);
    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_str);
    //dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-chain", &l_chain_str);
    //dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-tx", &l_tx_hash_str);

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
        dap_string_append_printf(l_str_out, "---------------\ntokens: %u\n", l_token_num_total);
        dap_chain_node_cli_set_reply_text(a_str_reply, l_str_out->str);
        dap_string_free(l_str_out, true);
        return 0;

    }
    // token info
    if(l_cmd == CMD_INFO) {
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
    if(l_cmd == CMD_TX) {

        const char *l_token_name_str = NULL;
        dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-name", &l_token_name_str);
        if(!l_token_name_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "command requires parameter '-name' <token name>");
                return -4;
            }

            dap_string_t *l_str_out = dap_string_new(NULL);
            // get first chain
            void *l_chain_tmp = (void*)0x1;
            dap_chain_t *l_chain_cur = dap_chain_enum(&l_chain_tmp);
            while(l_chain_cur) {
                // only selected net
                if(l_net->pub.id.uint64 == l_chain_cur->net_id.uint64) {
                    char *token_list_str = dap_db_history_filter(l_chain_cur, l_token_name_str, l_hash_out_type);
                    if(token_list_str){
                        dap_string_append(l_str_out, "%s\n", token_list_str);
                        dap_string_append(l_str_out, token_list_str);
                }
                // next chain
                dap_chain_enum_unlock();
                l_chain_cur = dap_chain_enum(&l_chain_tmp);
            }
            dap_chain_enum_unlock();
            dap_chain_node_cli_set_reply_text(a_str_reply, l_str_out->str);
            dap_string_free(l_str_out, true);
            return 0;


/*        bool l_is_all = dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-all", NULL);
        dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-addr", &l_addr_base58);
        dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-w", &l_wallet_name);
        dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_str);
        dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-chain", &l_chain_str);
        dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-tx", &l_tx_hash_str);

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
                        "tx_history requires parameter '-net' to be valid chain network name");
                return -3;
            }
        }
        //Select chain emission
        if(!l_chain_str) { // chain may be null -> then all chain use
            //dap_chain_node_cli_set_reply_text(a_str_reply, "command requires parameter '-chain'");
            //return -4;
        } else {
            if((l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_str)) == NULL) { // Can't find such chain
                dap_chain_node_cli_set_reply_text(a_str_reply,
                        "command requires parameter '-chain' to be valid chain name in chain net %s",
                        l_net_str);
                return -5;
            }
        }
        */
    }
    return 0;
}


