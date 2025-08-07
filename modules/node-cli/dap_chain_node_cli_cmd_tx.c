/*
 * Authors:
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2019
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

#include <stdbool.h>
#include <stddef.h>
#include <pthread.h>
#include <string.h>
#include "dap_chain_datum_tx.h"
#include "uthash.h"
#include "dap_cli_server.h"
#include "dap_common.h"
#include "dap_enc_base58.h"
#include "dap_strfuncs.h"
#include "dap_string.h"
#include "dap_list.h"
#include "dap_hash.h"
#include "dap_time.h"
#include "dap_chain_node_cli_cmd.h"
#include "dap_chain_datum.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_node_cli_cmd_tx.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_ledger.h"
#include "dap_chain_mempool.h"
#include "dap_math_convert.h"
#include "dap_json_rpc_errors.h"
#include "dap_chain_srv.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_wallet.h"
#include "dap_chain_wallet_cache.h"
#include "dap_enc_base64.h"
#include "dap_chain_net_tx.h"

#define LOG_TAG "chain_node_cli_cmd_tx"

static bool s_dap_chain_datum_tx_out_data(json_object* a_json_arr_reply,
                                   dap_chain_datum_tx_t *a_datum,
                                   dap_ledger_t *a_ledger,
                                   json_object * json_obj_out,
                                   const char *a_hash_out_type,
                                   dap_chain_hash_fast_t *a_tx_hash,
                                   int a_version);

static json_object *s_tx_history_to_json(json_object* a_json_arr_reply,
                                  dap_chain_hash_fast_t* a_tx_hash,
                                  dap_hash_fast_t * l_atom_hash,
                                  dap_chain_datum_tx_t * l_tx,
                                  dap_chain_t * a_chain, 
                                  const char *a_hash_out_type, 
                                  dap_chain_datum_iter_t *a_datum_iter,
                                  int l_ret_code,
                                  bool out_brief,
                                  int a_version);


/**
 * @brief s_chain_tx_hash_processed_ht_free
 * free l_current_hash->hash, l_current_hash, l_hash_processed
 * @param l_hash_processed dap_chain_tx_hash_processed_ht_t
 */
void s_dap_chain_tx_hash_processed_ht_free(dap_chain_tx_hash_processed_ht_t **l_hash_processed)
{
    if (!l_hash_processed || !*l_hash_processed)
        return;
    dap_chain_tx_hash_processed_ht_t *l_tmp, *l_current_hash;
    HASH_ITER(hh, *l_hash_processed, l_current_hash, l_tmp) {
        HASH_DEL(*l_hash_processed, l_current_hash);
        DAP_DELETE(l_current_hash);
    }
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

static bool s_dap_chain_datum_tx_out_data(json_object* a_json_arr_reply,
                                          dap_chain_datum_tx_t *a_datum,
                                          dap_ledger_t *a_ledger,
                                          json_object * json_obj_out,
                                          const char *a_hash_out_type,
                                          dap_chain_hash_fast_t *a_tx_hash,
                                          int a_version)
{
    char l_tx_hash_str[70]={0};
    char l_tmp_buf[DAP_TIME_STR_SIZE];
    const char *l_ticker = a_ledger
            ? dap_ledger_tx_get_token_ticker_by_hash(a_ledger, a_tx_hash)
            : NULL;
    if (!l_ticker)
        return false;
    const char *l_description = dap_ledger_get_description_by_ticker(a_ledger, l_ticker);
    dap_time_to_str_rfc822(l_tmp_buf, DAP_TIME_STR_SIZE, a_datum->header.ts_created);
    dap_chain_hash_fast_to_str(a_tx_hash,l_tx_hash_str,sizeof(l_tx_hash_str));
    json_object_object_add(json_obj_out, a_version == 1 ? "Datum_tx_hash" : "datum_tx_hash", json_object_new_string(l_tx_hash_str));
    json_object_object_add(json_obj_out, a_version == 1 ? "TS_Created" : "ts_created", json_object_new_string(l_tmp_buf));
    json_object_object_add(json_obj_out, a_version == 1 ? "Token_ticker" : "token_ticker", json_object_new_string(l_ticker));
    json_object_object_add(json_obj_out, a_version == 1 ? "Token_description" : "token_description", l_description ? json_object_new_string(l_description)
                                                                            : json_object_new_null());
    dap_chain_datum_dump_tx_json(a_json_arr_reply, a_datum, l_ticker, json_obj_out, a_hash_out_type, a_tx_hash, a_ledger->net->pub.id, a_version);
    json_object *json_arr_items = json_object_new_array();
    bool l_spent = false;
    byte_t *l_item; size_t l_size; int i, l_out_idx = -1;
    TX_ITEM_ITER_TX_TYPE(l_item, TX_ITEM_TYPE_OUT_ALL, l_size, i, a_datum) {
        ++l_out_idx;
        dap_hash_fast_t l_spender = { };
        json_object *l_json_obj_out = NULL, *l_json_arr_colours = NULL;
        if ( dap_ledger_tx_hash_is_used_out_item(a_ledger, a_tx_hash, l_out_idx, &l_spender) ) {
            char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE] = { '\0' };
            dap_hash_fast_to_str(&l_spender, l_hash_str, sizeof(l_hash_str));
            l_json_obj_out = json_object_new_object();
            json_object_object_add(l_json_obj_out, a_version == 1 ? "OUT - " : "out", json_object_new_int(l_out_idx));
            json_object_object_add(l_json_obj_out, a_version == 1 ? "is spent by tx" : "spent_by_tx", json_object_new_string(l_hash_str));
            l_spent = true;
        }
        dap_list_t *l_trackers = dap_ledger_tx_get_trackers(a_ledger, a_tx_hash, l_out_idx);
        if (l_trackers) {
            if (!l_json_obj_out) {
                l_json_obj_out = json_object_new_object();
                json_object_object_add(l_json_obj_out, "out_number", json_object_new_int(l_out_idx));
            }
            l_json_arr_colours = json_object_new_array();
            json_object_object_add(l_json_obj_out, "trackers", l_json_arr_colours);
        }
        for (dap_list_t *it = l_trackers; it; it = it->next) {
            dap_ledger_tracker_t *l_tracker = it->data;
            json_object *l_json_obj_tracker = json_object_new_object();
            json_object_array_add(l_json_arr_colours, l_json_obj_tracker);
            const char *l_voling_hash_str = dap_hash_fast_to_str_static(&l_tracker->voting_hash);
            json_object_object_add(l_json_obj_tracker, "voting_hash", json_object_new_string(l_voling_hash_str));
            json_object *l_json_arr_tracker_items = json_object_new_array();
            json_object_object_add(l_json_obj_tracker, "items", l_json_arr_tracker_items);
            for (dap_ledger_tracker_item_t *l_item = l_tracker->items; l_item; l_item = l_item->next) {
                json_object *l_json_obj_tracker_item = json_object_new_object();
                json_object_array_add(l_json_arr_tracker_items, l_json_obj_tracker_item);
                const char *l_pkey_hash_str = dap_hash_fast_to_str_static(&l_item->pkey_hash);
                json_object_object_add(l_json_obj_tracker_item, "pkey_hash", json_object_new_string(l_pkey_hash_str));
                const char *l_coloured_coins, *l_coloured_value = dap_uint256_to_char(l_item->coloured_value, &l_coloured_coins);
                json_object_object_add(l_json_obj_tracker_item, "coloured_coins", json_object_new_string(l_coloured_coins));
                json_object_object_add(l_json_obj_tracker_item, "coloured_value", json_object_new_string(l_coloured_value));
            }
        }
        if (l_json_obj_out)
            json_object_array_add(json_arr_items, l_json_obj_out);
    }
    json_object_object_add(json_obj_out, a_version == 1 ? "Spent OUTs" : "spent_outs", json_arr_items);
    json_object_object_add(json_obj_out, a_version == 1 ? "all OUTs yet unspent" : "all_outs_yet_unspent", l_spent ? json_object_new_string("no") : json_object_new_string("yes"));
    return true;
}

static json_object *s_tx_history_to_json(json_object* a_json_arr_reply,
                                         dap_chain_hash_fast_t* a_tx_hash,
                                         dap_hash_fast_t * l_atom_hash,
                                         dap_chain_datum_tx_t * l_tx,
                                         dap_chain_t * a_chain, 
                                         const char *a_hash_out_type, 
                                         dap_chain_datum_iter_t *a_datum_iter,
                                         int l_ret_code,
                                         bool brief_out,
                                         int a_version)
{
    const char *l_tx_token_description = NULL;
    json_object* json_obj_datum = json_object_new_object();
    if (!json_obj_datum) {
        return NULL;
    }

    dap_ledger_t *l_ledger = dap_chain_net_by_id(a_chain->net_id)->pub.ledger;
    const char *l_tx_token_ticker = a_datum_iter ?
                      a_datum_iter->token_ticker : dap_ledger_tx_get_token_ticker_by_hash(l_ledger, a_tx_hash);
    if (!l_ret_code) {
        json_object_object_add(json_obj_datum, "status", json_object_new_string("ACCEPTED"));
        l_tx_token_description = dap_ledger_get_description_by_ticker(l_ledger, l_tx_token_ticker);
    } else {
        json_object_object_add(json_obj_datum, "status", json_object_new_string("DECLINED"));
    }

    if (l_atom_hash) {
        const char *l_atom_hash_str = dap_strcmp(a_hash_out_type, "hex")
                            ? dap_enc_base58_encode_hash_to_str_static(l_atom_hash)
                            : dap_chain_hash_fast_to_str_static(l_atom_hash);
        json_object_object_add(json_obj_datum, "atom_hash", json_object_new_string(l_atom_hash_str));
        dap_chain_atom_iter_t *l_iter = a_chain->callback_atom_iter_create(a_chain, c_dap_chain_cell_id_null, l_atom_hash);
        size_t l_size = 0;
        if(a_chain->callback_atom_find_by_hash(l_iter, l_atom_hash, &l_size) != NULL){
            uint64_t l_block_count = a_chain->callback_count_atom(a_chain);
            uint64_t l_confirmations = l_block_count - l_iter->cur_num;
            json_object_object_add(json_obj_datum, "confirmations", json_object_new_uint64(l_confirmations));
        }
        a_chain->callback_atom_iter_delete(l_iter);
    }

    const char *l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                        ? dap_enc_base58_encode_hash_to_str_static(a_tx_hash)
                        : dap_chain_hash_fast_to_str_static(a_tx_hash);
    json_object_object_add(json_obj_datum, "hash", json_object_new_string(l_hash_str));
    
    json_object_object_add(json_obj_datum, "token_ticker", json_object_new_string(l_tx_token_ticker ? l_tx_token_ticker : "UNKNOWN"));
    if (l_tx_token_description) 
        json_object_object_add(json_obj_datum, "token_description", json_object_new_string(l_tx_token_description));

    json_object_object_add(json_obj_datum, "ret_code", json_object_new_int(l_ret_code));
    json_object_object_add(json_obj_datum, "ret_code_str", json_object_new_string(dap_ledger_check_error_str(l_ret_code)));

    dap_chain_srv_uid_t uid;
    char *service_name;
    dap_chain_tx_tag_action_type_t action;
    bool srv_found = a_datum_iter ? a_datum_iter->uid.uint64 ? true : false
                                  : dap_ledger_tx_service_info(l_ledger, a_tx_hash, &uid, &service_name, &action);
    if (a_datum_iter)action = a_datum_iter->action;

    if (srv_found)
    {
        //json_object_object_add(json_obj_datum, "service", json_object_new_string(service_name));
        json_object_object_add(json_obj_datum, "action", json_object_new_string(dap_ledger_tx_action_str(action)));
    }
    else
    {   
        //json_object_object_add(json_obj_datum, "service", json_object_new_string("UNKNOWN"));
        json_object_object_add(json_obj_datum, "action", json_object_new_string("UNKNOWN"));
    }
    json_object_object_add(json_obj_datum, "batching", json_object_new_string(!dap_chain_datum_tx_item_get_tsd_by_type(l_tx, DAP_CHAIN_DATUM_TRANSFER_TSD_TYPE_OUT_COUNT) ? "false" : "true"));
    if(!brief_out)
    {        
        dap_chain_datum_dump_tx_json(a_json_arr_reply, l_tx, l_tx_token_ticker ? l_tx_token_ticker : NULL,
                                     json_obj_datum, a_hash_out_type, a_tx_hash, a_chain->net_id, a_version);
    }

    return json_obj_datum;
}

json_object * dap_db_history_tx(json_object* a_json_arr_reply,
                      dap_chain_hash_fast_t* a_tx_hash, 
                      dap_chain_t * a_chain, 
                      const char *a_hash_out_type,
                      dap_chain_net_t *l_net,
                      int a_version)

{
    if (!a_chain->callback_datum_find_by_hash) {
        log_it(L_WARNING, "Not defined callback_datum_find_by_hash for chain \"%s\"", a_chain->name);
        return NULL;
    }

    int l_ret_code = 0;
    dap_hash_fast_t l_atom_hash = {0};
    //search tx
    dap_chain_datum_t *l_datum = a_chain->callback_datum_find_by_hash(a_chain, a_tx_hash, &l_atom_hash, &l_ret_code);
    dap_chain_datum_tx_t *l_tx = l_datum  && l_datum->header.type_id == DAP_CHAIN_DATUM_TX ?
                                 (dap_chain_datum_tx_t *)l_datum->data : NULL;

    if (l_tx) {
        return s_tx_history_to_json(a_json_arr_reply, a_tx_hash, &l_atom_hash, l_tx, a_chain, a_hash_out_type, NULL, l_ret_code, false, a_version);
    } else {
        const char *l_tx_hash_str = dap_strcmp(a_hash_out_type, "hex")
                ? dap_enc_base58_encode_hash_to_str_static(a_tx_hash)
                : dap_chain_hash_fast_to_str_static(a_tx_hash);
        dap_json_rpc_error_add(a_json_arr_reply, -1, "TX hash %s not founds in chains", l_tx_hash_str);
        return NULL;
    }
}

static void s_tx_header_print(json_object* json_obj_datum, dap_chain_tx_hash_processed_ht_t **a_tx_data_ht,
                              dap_chain_datum_tx_t *a_tx, dap_chain_t *a_chain, const char *a_hash_out_type, 
                              dap_ledger_t *a_ledger, dap_chain_hash_fast_t *a_tx_hash, dap_chain_hash_fast_t *a_atom_hash, const char* a_token_ticker, 
                              int a_ret_code, dap_chain_tx_tag_action_type_t a_action, dap_chain_srv_uid_t a_uid)
{
    bool l_declined = false;
    // transaction time
    char l_time_str[DAP_TIME_STR_SIZE] = "unknown";                                /* Prefill string */
    if (a_tx->header.ts_created)
        dap_time_to_str_rfc822(l_time_str, DAP_TIME_STR_SIZE, a_tx->header.ts_created); /* Convert ts to  "Sat May 17 01:17:08 2014" */
    dap_chain_tx_hash_processed_ht_t *l_tx_data = NULL;
    HASH_FIND(hh, *a_tx_data_ht, a_tx_hash, sizeof(*a_tx_hash), l_tx_data);
    if (l_tx_data)  // this tx already present in ledger (double)
        l_declined = true;
    else {
        l_tx_data = DAP_NEW_Z(dap_chain_tx_hash_processed_ht_t);
        if (!l_tx_data) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            return;
        }
        l_tx_data->hash = *a_tx_hash;
        HASH_ADD(hh, *a_tx_data_ht, hash, sizeof(*a_tx_hash), l_tx_data);
        
               
        if (a_ret_code)
            l_declined = true;
    }

    char *l_tx_hash_str, *l_atom_hash_str;
    if (!dap_strcmp(a_hash_out_type, "hex")) {
        l_tx_hash_str = dap_chain_hash_fast_to_str_new(a_tx_hash);
        l_atom_hash_str = dap_chain_hash_fast_to_str_new(a_atom_hash);
    } else {
        l_tx_hash_str = dap_enc_base58_encode_hash_to_str(a_tx_hash);
        l_atom_hash_str = dap_enc_base58_encode_hash_to_str(a_atom_hash);
    }
    json_object_object_add(json_obj_datum, "status", json_object_new_string(l_declined ? "DECLINED" : "ACCEPTED"));
    json_object_object_add(json_obj_datum, "hash", json_object_new_string(l_tx_hash_str));
    json_object_object_add(json_obj_datum, "atom_hash", json_object_new_string(l_atom_hash_str));
    json_object_object_add(json_obj_datum, "ret_code", json_object_new_int(a_ret_code));
    json_object_object_add(json_obj_datum, "ret_code_str", json_object_new_string(dap_ledger_check_error_str(a_ret_code)));


    bool srv_found = a_uid.uint64 ? true : false;
    
    if (srv_found)
    {
        json_object_object_add(json_obj_datum, "action", json_object_new_string(dap_ledger_tx_action_str(a_action)));
        json_object_object_add(json_obj_datum, "service", json_object_new_string(dap_ledger_tx_tag_str_by_uid(a_uid)));
    }
    else
    {
        json_object_object_add(json_obj_datum, "action", json_object_new_string("UNKNOWN"));
        json_object_object_add(json_obj_datum, "service", json_object_new_string("UNKNOWN"));
    }

    json_object_object_add(json_obj_datum, "batching", json_object_new_string(!dap_chain_datum_tx_item_get_tsd_by_type(a_tx, DAP_CHAIN_DATUM_TRANSFER_TSD_TYPE_OUT_COUNT) ? "false" : "true"));
    json_object_object_add(json_obj_datum, "tx_created", json_object_new_string(l_time_str));

    DAP_DELETE(l_tx_hash_str);
    DAP_DELETE(l_atom_hash_str);
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
json_object* dap_db_history_addr(json_object* a_json_arr_reply, dap_chain_addr_t *a_addr, dap_chain_t *a_chain, 
                                 const char *a_hash_out_type, const char * l_addr_str, json_object *json_obj_summary,
                                 size_t a_limit, size_t a_offset, bool a_brief, const char *a_srv, dap_chain_tx_tag_action_type_t a_action, bool a_head,
                                 int a_version)
{
    json_object* json_obj_datum = json_object_new_array();
    if (!json_obj_datum){
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        dap_json_rpc_error_add(a_json_arr_reply, -44, "Memory allocation error");
        return NULL;
    }

    // add address
    json_object * json_obj_addr = json_object_new_object();
    json_object_object_add(json_obj_addr, a_version == 1 ? "address" : "addr", json_object_new_string(l_addr_str));
    json_object_array_add(json_obj_datum, json_obj_addr);

    dap_chain_tx_hash_processed_ht_t *l_tx_data_ht = NULL;
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    if (!l_net) {
        log_it(L_WARNING, "Can't find net by specified chain %s", a_chain->name);
        dap_json_rpc_error_add(a_json_arr_reply, -1, "Can't find net by specified chain %s", a_chain->name);
        json_object_put(json_obj_datum);
        return NULL;
    }
    dap_ledger_t *l_ledger = l_net->pub.ledger;
    const char *l_native_ticker = l_net->pub.native_ticker;
    if (!a_chain->callback_datum_iter_create) {
        log_it(L_WARNING, "Not defined callback_datum_iter_create for chain \"%s\"", a_chain->name);
        dap_json_rpc_error_add(a_json_arr_reply, -1, "Not defined callback_datum_iter_create for chain \"%s\"", a_chain->name);
        json_object_put(json_obj_datum);
        return NULL;
    }

    dap_chain_addr_t  l_net_fee_addr = {};
    bool l_net_fee_used = dap_chain_net_tx_get_fee(l_net->pub.id, NULL, &l_net_fee_addr);
    bool look_for_unknown_service = (a_srv && strcmp(a_srv,"unknown") == 0);
    size_t l_arr_start = 0;
    size_t l_arr_end = 0;

    dap_chain_set_offset_limit_json(json_obj_datum, &l_arr_start, &l_arr_end, a_limit, a_offset, a_chain->callback_count_tx(a_chain),false);
    
    size_t i_tmp = 0;
    size_t
            l_count = 0,
            l_tx_ledger_accepted = 0,
            l_tx_ledger_rejected = 0;
   
    dap_hash_fast_t l_curr_tx_hash = {};
    bool l_from_cache = dap_chain_wallet_cache_tx_find_in_history(a_addr, NULL, NULL, NULL, NULL, NULL, &l_curr_tx_hash) == 0 ? true : false;
    if (l_from_cache && a_addr->net_id.uint64 != l_net->pub.id.uint64){
        log_it(L_WARNING, "Can't find wallet with addr %s in net %s", l_addr_str, l_net->pub.name);
        dap_json_rpc_error_add(a_json_arr_reply, -1, "Can't find wallet with addr %s in net %s", l_addr_str, l_net->pub.name);
        json_object_put(json_obj_datum);
        return NULL;
    }
    memset(&l_curr_tx_hash, 0, sizeof(dap_hash_fast_t));
    dap_chain_datum_tx_t *l_tx = NULL;
    
 
    dap_chain_datum_iter_t *l_datum_iter = NULL;
    dap_chain_wallet_cache_iter_t *l_wallet_cache_iter = NULL;
    dap_chain_datum_callback_iters  iter_begin = NULL;
    dap_chain_datum_callback_iters  iter_direc = NULL;
    dap_chain_wallet_getting_type_t cache_iter_begin = DAP_CHAIN_WALLET_CACHE_GET_FIRST, cache_iter_direc = DAP_CHAIN_WALLET_CACHE_GET_NEXT;


    if (!l_from_cache){
        l_datum_iter = a_chain->callback_datum_iter_create(a_chain);   
        iter_begin = a_head ? a_chain->callback_datum_iter_get_first
                        : a_chain->callback_datum_iter_get_last;
        iter_direc = a_head ? a_chain->callback_datum_iter_get_next
                        : a_chain->callback_datum_iter_get_prev;         
    } else{
        l_wallet_cache_iter = dap_chain_wallet_cache_iter_create(*a_addr);
        cache_iter_begin = a_head ? DAP_CHAIN_WALLET_CACHE_GET_FIRST : DAP_CHAIN_WALLET_CACHE_GET_LAST;
        cache_iter_direc = a_head ? DAP_CHAIN_WALLET_CACHE_GET_NEXT : DAP_CHAIN_WALLET_CACHE_GET_PREVIOUS;
    }      

    dap_chain_datum_t *l_datum = NULL;
    dap_chain_datum_tx_t *l_cur_tx_cache = NULL;
    if (!l_from_cache)
        l_datum = iter_begin(l_datum_iter);
    else
        l_cur_tx_cache = dap_chain_wallet_cache_iter_get(l_wallet_cache_iter, cache_iter_begin);

    while (l_datum || l_cur_tx_cache){
        
        if (l_datum && l_datum->header.type_id != DAP_CHAIN_DATUM_TX)
            // go to next datum
            goto next_step;   

        if (i_tmp >= l_arr_end) {
            ++i_tmp;
            goto next_step;
        }     
        // it's a transaction     
        l_tx = l_from_cache ? l_cur_tx_cache : (dap_chain_datum_tx_t *)l_datum->data;

        bool l_is_need_correction = false;
        bool l_continue = true;
        uint256_t l_corr_value = {}, l_cond_value = {};
        bool l_recv_from_cond = false, l_send_to_same_cond = false, l_found_out_to_same_addr_from_out_cond = false;
        json_object *l_corr_object = NULL, *l_cond_recv_object = NULL, *l_cond_send_object = NULL;
        
        dap_chain_addr_t *l_src_addr = NULL;
        bool l_base_tx = false, l_reward_collect = false;
        const char *l_noaddr_token = NULL;

        dap_hash_fast_t l_tx_hash = l_from_cache ? *l_wallet_cache_iter->cur_hash : *l_datum_iter->cur_hash;
        const char *l_src_token = l_from_cache ? l_wallet_cache_iter->token_ticker : l_datum_iter->token_ticker;
        int l_ret_code = l_from_cache ? l_wallet_cache_iter->ret_code : l_datum_iter->ret_code;
        uint32_t l_action = l_from_cache ? l_wallet_cache_iter->action : l_datum_iter->action;
         dap_hash_fast_t l_atom_hash = l_from_cache ? *l_wallet_cache_iter->cur_atom_hash : *l_datum_iter->cur_atom_hash;
        dap_chain_srv_uid_t l_uid = l_from_cache ? l_wallet_cache_iter->uid : l_datum_iter->uid;

        int l_src_subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_UNDEFINED;
        uint8_t *l_tx_item = NULL;
        size_t l_size; int i, q = 0;
        // Check all INs
        TX_ITEM_ITER_TX_TYPE(l_tx_item, TX_ITEM_TYPE_IN_ALL, l_size, i, l_tx) {
            dap_chain_hash_fast_t *l_tx_prev_hash = NULL;
            int l_tx_prev_out_idx;
            dap_chain_datum_tx_t *l_tx_prev = NULL;
            switch (*l_tx_item) {
            case TX_ITEM_TYPE_IN: {
                dap_chain_tx_in_t *l_tx_in = (dap_chain_tx_in_t *)l_tx_item;
                l_tx_prev_hash = &l_tx_in->header.tx_prev_hash;
                l_tx_prev_out_idx = l_tx_in->header.tx_out_prev_idx;
            } break;
            case TX_ITEM_TYPE_IN_COND: {
                dap_chain_tx_in_cond_t *l_tx_in_cond = (dap_chain_tx_in_cond_t *)l_tx_item;
                l_tx_prev_hash = &l_tx_in_cond->header.tx_prev_hash;
                l_tx_prev_out_idx = l_tx_in_cond->header.tx_out_prev_idx;
            } break;
            case TX_ITEM_TYPE_IN_EMS: {
                dap_chain_tx_in_ems_t *l_tx_in_ems = (dap_chain_tx_in_ems_t *)l_tx_item;
                l_base_tx = true;
                l_noaddr_token = l_tx_in_ems->header.ticker;
            } break;
            case TX_ITEM_TYPE_IN_REWARD: {
                l_base_tx = l_reward_collect = true;
                l_noaddr_token = l_native_ticker;
            }
            default:
                continue;
            }

            dap_chain_datum_t *l_datum_prev = l_tx_prev_hash ?
                        a_chain->callback_datum_find_by_hash(a_chain, l_tx_prev_hash, NULL, NULL) : NULL;
            l_tx_prev = l_datum_prev && l_datum_prev->header.type_id == DAP_CHAIN_DATUM_TX ? (dap_chain_datum_tx_t *)l_datum_prev->data : NULL;
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
                    break;
                case TX_ITEM_TYPE_OUT_STD:
                    l_src_addr = &((dap_chain_tx_out_std_t *)l_prev_out_union)->addr;
                    break;
                case TX_ITEM_TYPE_OUT_COND: {
                    dap_chain_tx_out_cond_t *l_cond_prev = (dap_chain_tx_out_cond_t *)l_prev_out_union;
                    l_src_subtype = l_cond_prev->header.subtype;
                    if (l_cond_prev->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE)
                        l_noaddr_token = l_native_ticker;
                    else {
                        l_recv_from_cond = true;
                        l_cond_value = l_cond_prev->header.value;
                        l_noaddr_token = l_src_token;
                    }
                } break;
                default:
                    break;
                }
            }
            if (l_src_addr && !dap_chain_addr_compare(l_src_addr, a_addr))
                break;  //it's not our addr
            
        }        

        // find OUT items
        bool l_header_printed = false;
        uint256_t l_fee_sum = uint256_0;
        dap_list_t *l_list_out_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_OUT_ALL, NULL);
        json_object * j_arr_data = json_object_new_array();
        json_object * j_obj_tx = json_object_new_object();
        if (!j_obj_tx || !j_arr_data) {
            dap_json_rpc_allocation_error(a_json_arr_reply);
            json_object_put(j_obj_tx);
            json_object_put(j_arr_data);
            return NULL;
        }
        if (!l_src_addr) {
            bool l_dst_addr_present = false;
            for (dap_list_t *it = l_list_out_items; it; it = it->next) {
                uint8_t l_type = *(uint8_t *)it->data;
                dap_chain_addr_t *l_dst_addr = NULL;
                switch (l_type) {
                case TX_ITEM_TYPE_OUT:
                    l_dst_addr = &((dap_chain_tx_out_t *)it->data)->addr;
                    break;
                case TX_ITEM_TYPE_OUT_EXT:
                    l_dst_addr = &((dap_chain_tx_out_ext_t *)it->data)->addr;
                    break;
                case TX_ITEM_TYPE_OUT_STD:
                    l_dst_addr = &((dap_chain_tx_out_std_t *)it->data)->addr;
                default:
                    break;
                }
                if (l_dst_addr && dap_chain_addr_compare(l_dst_addr, a_addr)) {
                    l_dst_addr_present = true;
                    break;
                }
            }
            if (!l_dst_addr_present)
            {
                json_object_put(j_arr_data);
                j_arr_data = NULL;
                json_object_put(j_obj_tx);
                dap_list_free(l_list_out_items);
                goto next_step;
            }                
        }

        for (dap_list_t *it = l_list_out_items; it; it = it->next) {
            dap_chain_addr_t *l_dst_addr = NULL;
            uint8_t l_type = *(uint8_t *)it->data;
            uint256_t l_value;
            const char *l_dst_token = NULL;
            switch (l_type) {
            case TX_ITEM_TYPE_OUT:
                l_dst_addr = &((dap_chain_tx_out_t *)it->data)->addr;
                l_value = ((dap_chain_tx_out_t *)it->data)->header.value;
                l_dst_token = l_src_token;
                break;
            case TX_ITEM_TYPE_OUT_EXT:
                l_dst_addr = &((dap_chain_tx_out_ext_t *)it->data)->addr;
                l_value = ((dap_chain_tx_out_ext_t *)it->data)->header.value;
                l_dst_token = ((dap_chain_tx_out_ext_t *)it->data)->token;
                break;
            case TX_ITEM_TYPE_OUT_STD:
                l_dst_addr = &((dap_chain_tx_out_std_t *)it->data)->addr;
                l_value = ((dap_chain_tx_out_std_t *)it->data)->value;
                l_dst_token = ((dap_chain_tx_out_std_t *)it->data)->token;
                break;
            case TX_ITEM_TYPE_OUT_COND:
                l_value = ((dap_chain_tx_out_cond_t *)it->data)->header.value;
                if (((dap_chain_tx_out_cond_t *)it->data)->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE) {
                    SUM_256_256(l_fee_sum, l_value, &l_fee_sum);
                    l_dst_token = l_native_ticker;
                } else
                    l_dst_token = l_src_token;
            default:
                break;
            }

            if (l_src_addr && l_dst_addr &&
                    dap_chain_addr_compare(l_dst_addr, l_src_addr) &&
                    (!l_recv_from_cond || (l_noaddr_token && (dap_strcmp(l_noaddr_token, l_dst_token) || l_found_out_to_same_addr_from_out_cond))))
                continue;   // sent to self (coinback)

            if (l_dst_addr && l_net_fee_used && dap_chain_addr_compare(&l_net_fee_addr, l_dst_addr))
                SUM_256_256(l_fee_sum, l_value, &l_fee_sum);
            
            //tag
            const char *l_service_name = NULL;
            bool srv_found = l_uid.uint64 ? true : false;
            l_service_name = dap_ledger_tx_action_str(l_action);
            if (!(l_action & a_action))
                continue;
            if (a_srv) {
                //skip if looking for UNKNOWN + it is known
                if (look_for_unknown_service && srv_found)
                    continue;                    
                //skip if search condition provided, it not UNKNOWN and found name not match
                if (!look_for_unknown_service && (!srv_found || strcmp(l_service_name, a_srv) != 0))
                    continue;
            }

            if (l_dst_addr && dap_chain_addr_compare(l_dst_addr, a_addr)) {  
                if (i_tmp >= l_arr_start)
                    l_continue = false;
                else {
                    i_tmp++;
                    break;
                }             
                if (!l_header_printed) {               
                    s_tx_header_print(j_obj_tx, &l_tx_data_ht, l_tx, a_chain,
                                    a_hash_out_type, l_ledger, &l_tx_hash, &l_atom_hash, l_src_token, 
                                    l_ret_code, l_action, l_uid);
                    l_header_printed = true;
                    l_count++;
                    i_tmp++;
                    l_src_token ? l_tx_ledger_accepted++ : l_tx_ledger_rejected++;                    
                }
                const char *l_src_str = NULL;
                if (l_base_tx)
                    l_src_str = l_reward_collect ? "reward collecting" : "emission";
                else if (l_src_addr && dap_strcmp(l_dst_token, l_noaddr_token))
                    l_src_str = dap_chain_addr_to_str_static(l_src_addr);
                else{
                    l_src_str = dap_chain_tx_out_cond_subtype_to_str(l_src_subtype);
                    if (l_src_addr && !dap_strcmp(l_dst_token, l_noaddr_token) && l_recv_from_cond)
                        l_found_out_to_same_addr_from_out_cond = true;
                }
                if (l_recv_from_cond)
                    l_value = l_cond_value;
                else if (!dap_strcmp(l_native_ticker, l_noaddr_token)) {
                    l_is_need_correction = true;
                    l_corr_value = l_value;
                }
                const char *l_coins_str, *l_value_str = dap_uint256_to_char(l_value, &l_coins_str);                 

                json_object * j_obj_data = json_object_new_object();
                if (!j_obj_data) {
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    json_object_put(j_obj_tx);
                    json_object_put(j_arr_data);
                    return NULL;
                }                
                json_object_object_add(j_obj_data, "tx_type", json_object_new_string("recv"));
                json_object_object_add(j_obj_data, "recv_coins", json_object_new_string(l_coins_str));
                json_object_object_add(j_obj_data, "recv_datoshi", json_object_new_string(l_value_str));
                json_object_object_add(j_obj_data, "token", l_dst_token ? json_object_new_string(l_dst_token)
                                                                            : json_object_new_string("UNKNOWN"));
                json_object_object_add(j_obj_data, "source_address", json_object_new_string(l_src_str));
                if (l_recv_from_cond && !l_cond_recv_object)
                    l_cond_recv_object = j_obj_data;
                else
                    json_object_array_add(j_arr_data, j_obj_data);
                if (l_is_need_correction)
                    l_corr_object = j_obj_data;
                
            } else if (!l_src_addr || (dap_chain_addr_compare(l_src_addr, a_addr) && (!l_recv_from_cond || 
                (!l_dst_addr || dap_strcmp(l_dst_token, l_noaddr_token) || dap_chain_addr_compare(l_dst_addr, &l_net_fee_addr))))) {
                if (!l_dst_addr && ((dap_chain_tx_out_cond_t *)it->data)->header.subtype == l_src_subtype && l_src_subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE)
                    continue;
                if (!l_src_addr && l_dst_addr && !dap_chain_addr_compare(l_dst_addr, &l_net_fee_addr))
                    continue;
                if (i_tmp >= l_arr_start)
                    l_continue = false;
                else {
                    i_tmp++;
                    break;
                }                               
                if (!l_header_printed) {                    
                    s_tx_header_print(j_obj_tx, &l_tx_data_ht, l_tx, a_chain,
                                    a_hash_out_type, l_ledger, &l_tx_hash, &l_atom_hash, l_src_token, 
                                    l_ret_code, l_action, l_uid);
                    l_header_printed = true;
                    l_count++;
                    i_tmp++;
                    l_src_token ? l_tx_ledger_accepted++ : l_tx_ledger_rejected++;
                }

                const char *l_dst_addr_str = NULL;
                if (l_dst_addr)
                    l_dst_addr_str = dap_chain_addr_to_str_static(l_dst_addr);
                else {
                    dap_chain_tx_out_cond_subtype_t l_dst_subtype = ((dap_chain_tx_out_cond_t *)it->data)->header.subtype;
                    l_dst_addr_str = dap_chain_tx_out_cond_subtype_to_str(l_dst_subtype);
                    if (l_recv_from_cond && l_dst_subtype != DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE && l_dst_subtype == l_src_subtype)
                        l_send_to_same_cond = true;
                }
                const char *l_coins_str, *l_value_str = dap_uint256_to_char(l_value, &l_coins_str);
                                
                json_object * j_obj_data = json_object_new_object();
                if (!j_obj_data) {
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    json_object_put(j_obj_tx);
                    json_object_put(j_arr_data);
                    return NULL;
                }                
                json_object_object_add(j_obj_data, "tx_type", json_object_new_string("send"));
                json_object_object_add(j_obj_data, "send_coins", json_object_new_string(l_coins_str));
                json_object_object_add(j_obj_data, "send_datoshi", json_object_new_string(l_value_str));
                json_object_object_add(j_obj_data, "token", l_dst_token ? json_object_new_string(l_dst_token)
                                                                        : json_object_new_string("UNKNOWN"));
                json_object_object_add(j_obj_data, "destination_address", json_object_new_string(l_dst_addr_str));
                if (l_send_to_same_cond && !l_cond_send_object)
                    l_cond_send_object = j_obj_data;
                else
                    json_object_array_add(j_arr_data, j_obj_data);
            }
        }  
        if (l_continue) {
            json_object_put(j_obj_tx);
            json_object_put(j_arr_data);
            goto next_step;
        }            

        if (l_is_need_correction) {
            SUM_256_256(l_corr_value, l_fee_sum, &l_corr_value);
            const char *l_coins_str, *l_value_str = dap_uint256_to_char(l_corr_value, &l_coins_str);
            json_object_object_add(l_corr_object, "recv_coins", json_object_new_string(l_coins_str));
            json_object_object_add(l_corr_object, "recv_datoshi", json_object_new_string(l_value_str));
        }
        if (l_send_to_same_cond && l_found_out_to_same_addr_from_out_cond) {
            uint256_t l_cond_recv_value = l_cond_value;
            json_object *l_cond_send_value_obj = json_object_object_get(l_cond_send_object, "send_datoshi");
            const char *l_cond_send_value_str = json_object_get_string(l_cond_send_value_obj);
            uint256_t l_cond_send_value = dap_uint256_scan_uninteger(l_cond_send_value_str);
            int l_direction = compare256(l_cond_recv_value, l_cond_send_value);
            if (l_direction > 0) {
                SUBTRACT_256_256(l_cond_recv_value, l_cond_send_value, &l_cond_recv_value);
                const char *l_coins_str, *l_value_str = dap_uint256_to_char(l_cond_recv_value, &l_coins_str);
                json_object_object_add(l_cond_recv_object, "recv_coins", json_object_new_string(l_coins_str));
                json_object_object_add(l_cond_recv_object, "recv_datoshi", json_object_new_string(l_value_str));
                json_object_array_add(j_arr_data, l_cond_recv_object);
            } else if (l_direction < 0) {
                SUBTRACT_256_256(l_cond_send_value, l_cond_recv_value, &l_cond_send_value);
                const char *l_coins_str, *l_value_str = dap_uint256_to_char(l_cond_send_value, &l_coins_str);
                json_object_object_add(l_cond_send_object, "send_coins", json_object_new_string(l_coins_str));
                json_object_object_add(l_cond_send_object, "send_datoshi", json_object_new_string(l_value_str));
                json_object_array_add(j_arr_data, l_cond_send_object);
            }
        } else if (l_recv_from_cond)
            json_object_array_add(j_arr_data, l_cond_recv_object);

        if (json_object_array_length(j_arr_data) > 0) {
            json_object_object_add(j_obj_tx, "data", j_arr_data);
            json_object_array_add(json_obj_datum, j_obj_tx);
        } else {
            json_object_put(j_arr_data);
            j_arr_data = NULL;
            json_object_put(j_obj_tx);
        }
        dap_list_free(l_list_out_items);

next_step:
        if (!l_from_cache)
            l_datum = iter_direc(l_datum_iter);
        else
            l_cur_tx_cache = dap_chain_wallet_cache_iter_get(l_wallet_cache_iter, cache_iter_direc);
    }
    if (l_datum_iter)
        a_chain->callback_datum_iter_delete(l_datum_iter);

    if (l_wallet_cache_iter)
        dap_chain_wallet_cache_iter_delete(l_wallet_cache_iter);

    // delete hashes
    s_dap_chain_tx_hash_processed_ht_free(&l_tx_data_ht);
    
    // if no history
    if (json_object_array_length(json_obj_datum) == 2) {
        json_object * json_empty_tx = json_object_new_object();
        if (!json_empty_tx) {
            dap_json_rpc_allocation_error(a_json_arr_reply);
            json_object_put(json_obj_datum);
            return NULL;
        }
        json_object_object_add(json_empty_tx, "status", json_object_new_string("empty"));        
        json_object_array_add(json_obj_datum, json_empty_tx);
    }    
    json_object_object_add(json_obj_summary, "network", json_object_new_string(l_net->pub.name));
    json_object_object_add(json_obj_summary, "chain", json_object_new_string(a_chain->name));
    json_object_object_add(json_obj_summary, a_version == 1 ? "accepted_tx" : "tx_accept_count", json_object_new_int(l_tx_ledger_accepted));
    json_object_object_add(json_obj_summary, a_version == 1 ? "rejected_tx" : "tx_reject_count", json_object_new_int(l_tx_ledger_rejected));
    json_object_object_add(json_obj_summary, a_version == 1 ? "tx_sum" : "tx_count", json_object_new_int(l_count));   
    json_object_object_add(json_obj_summary, "total_tx_count", json_object_new_int(i_tmp));  
    return json_obj_datum;
}

static int s_json_tx_history_pack(json_object* a_json_arr_reply, json_object** a_json_obj_datum, dap_chain_datum_iter_t *a_datum_iter,
                                  dap_chain_datum_t * a_datum,
                                  dap_chain_t *a_chain, dap_chain_tx_tag_action_type_t a_action,
                                  const char *a_hash_out_type, bool a_out_brief, size_t* a_accepted,
                                  size_t* a_rejected, bool a_look_for_unknown_service, const char *a_srv, int a_version)
{
    dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t*)a_datum->data;
    dap_hash_fast_t l_ttx_hash = {0};
    dap_hash_fast(l_tx, a_datum->header.data_size, &l_ttx_hash);

    const char *service_name = NULL;
    dap_chain_tx_tag_action_type_t l_action = DAP_CHAIN_TX_TAG_ACTION_UNKNOWN;
    //bool srv_found = a_datum_iter->uid.uint64 ? true : false;
    l_action = a_datum_iter->action;
    service_name = dap_ledger_tx_action_str(l_action);

    if (!(l_action & a_action))
        return 1;

    if (a_srv)
    {
        bool srv_found = a_datum_iter->uid.uint64 ? true : false;
        //skip if looking for UNKNOWN + it is known
        if (a_look_for_unknown_service && srv_found) {
            return 1;
        }

        //skip if search condition provided, it not UNKNOWN and found name not match
        if (!a_look_for_unknown_service && (!srv_found || strcmp(service_name, a_srv) != 0))
        {
            return 1;
        }
    }

    *a_json_obj_datum = s_tx_history_to_json(a_json_arr_reply, &l_ttx_hash, NULL, l_tx, a_chain, a_hash_out_type, a_datum_iter, a_datum_iter->ret_code, a_out_brief, a_version);
    if (!*a_json_obj_datum) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return 2;
    }
    if (a_datum_iter->ret_code == 0) {
        ++*a_accepted;
    } else {
        ++*a_rejected;
    }
    return 0;

}

json_object *dap_db_history_tx_all(json_object* a_json_arr_reply, dap_chain_t *a_chain, dap_chain_net_t *a_net,
                                   const char *a_hash_out_type, json_object *json_obj_summary,
                                   size_t a_limit, size_t a_offset, bool out_brief,
					const char *a_srv, dap_chain_tx_tag_action_type_t a_action, bool a_head, int a_version)
{
        log_it(L_DEBUG, "Start getting tx from chain");
        size_t
            l_tx_ledger_accepted = 0,
            l_tx_ledger_rejected = 0,
            l_count = 0,
            i_tmp = 0;
        int res = 0;        
        json_object * json_arr_out = json_object_new_array();
        json_object * json_tx_history = NULL;        
        size_t l_arr_start = 0;
        size_t l_arr_end = 0;

        dap_chain_set_offset_limit_json(json_arr_out, &l_arr_start, &l_arr_end, a_limit, a_offset, a_chain->callback_count_tx(a_chain),false);
        
        bool look_for_unknown_service = (a_srv && strcmp(a_srv,"unknown") == 0);
        // load transactions
        dap_chain_datum_iter_t *l_datum_iter = a_chain->callback_datum_iter_create(a_chain);
        
        dap_chain_datum_callback_iters  iter_begin;
        dap_chain_datum_callback_iters  iter_direc;
        iter_begin = a_head ? a_chain->callback_datum_iter_get_first
                            : a_chain->callback_datum_iter_get_last;
        iter_direc = a_head ? a_chain->callback_datum_iter_get_next
                            : a_chain->callback_datum_iter_get_prev;
        
        for (dap_chain_datum_t *l_datum = iter_begin(l_datum_iter);
                                l_datum;
                                l_datum = iter_direc(l_datum_iter))
        {
            if (i_tmp >= l_arr_end)
                break;
            if (l_datum->header.type_id != DAP_CHAIN_DATUM_TX)
                // go to next datum
                continue;
            
            if (i_tmp < l_arr_start) {
                i_tmp++;
                continue;
            }
            res = s_json_tx_history_pack(a_json_arr_reply, &json_tx_history, l_datum_iter, l_datum, a_chain, a_action, a_hash_out_type, out_brief,
                                        &l_tx_ledger_accepted, &l_tx_ledger_rejected, look_for_unknown_service, a_srv, a_version);
            if (res == 1)
                continue;
            else if (res == 2)
            {
                json_object_put(json_arr_out);
                return NULL;
            }
            json_object_object_add(json_tx_history, a_version == 1 ? "tx number" : "tx_num", json_object_new_uint64(l_count+1));                     
            json_object_array_add(json_arr_out, json_tx_history);
            ++i_tmp;
            l_count++;            
        }        
        log_it(L_DEBUG, "END getting tx from chain");
        a_chain->callback_datum_iter_delete(l_datum_iter);

        json_object_object_add(json_obj_summary, "network", json_object_new_string(a_net->pub.name));
        json_object_object_add(json_obj_summary, "chain", json_object_new_string(a_chain->name));
        json_object_object_add(json_obj_summary, "tx_sum", json_object_new_int(l_count));
        json_object_object_add(json_obj_summary, "accepted_tx", json_object_new_int(l_tx_ledger_accepted));
        json_object_object_add(json_obj_summary, "rejected_tx", json_object_new_int(l_tx_ledger_rejected));
        return json_arr_out;
}

json_object *s_get_ticker(json_object *a_jobj_tickers, const char *a_token_ticker) {
    json_object_object_foreach(a_jobj_tickers, key, value){
        if (dap_strcmp(a_token_ticker, key) == 0) {
            return value;
        }
    }
    return NULL;
}

/**
 * @brief show all tokens in chain
 *
 * @param a_chain
 * @param a_token_name
 * @param a_hash_out_type
 * @param a_token_num
 * @return char*
 */
static json_object* dap_db_chain_history_token_list(json_object* a_json_arr_reply, dap_chain_t * a_chain, const char *a_token_name, const char *a_hash_out_type, size_t *a_token_num, int a_version)
{
    json_object *l_jobj_tickers = json_object_new_object();
    if (!a_chain->callback_datum_iter_create) {
        log_it(L_WARNING, "Not defined datum iterators for chain \"%s\"", a_chain->name);
        return NULL;
    }    
    size_t l_token_num  = 0;
    dap_chain_datum_iter_t *l_datum_iter = a_chain->callback_datum_iter_create(a_chain);
    for (dap_chain_datum_t *l_datum = a_chain->callback_datum_iter_get_first(l_datum_iter);
            l_datum; l_datum = a_chain->callback_datum_iter_get_next(l_datum_iter)) {
        if (l_datum->header.type_id != DAP_CHAIN_DATUM_TOKEN)
            continue;
        size_t l_token_size = l_datum->header.data_size;
        dap_chain_datum_token_t *l_token = dap_chain_datum_token_read(l_datum->data, &l_token_size);
        if (a_token_name) {
            if (dap_strcmp(a_token_name, l_token->ticker) != 0) {
                DAP_DELETE(l_token);
                continue;
            }
        }
        json_object *l_jobj_ticker = s_get_ticker(l_jobj_tickers, l_token->ticker);
        json_object *l_jobj_decls = NULL;
        json_object *l_jobj_updates = NULL;
        if (!l_jobj_ticker) {
            l_jobj_ticker = json_object_new_object();
            dap_ledger_t *l_ledger = dap_chain_net_by_id(a_chain->net_id)->pub.ledger;
            json_object *l_current_state = dap_ledger_token_info_by_name(l_ledger, l_token->ticker, a_version);
            json_object_object_add(l_jobj_ticker, a_version == 1 ? "current state" : "current_state", l_current_state);
            l_jobj_decls = json_object_new_array();
            l_jobj_updates = json_object_new_array();
            json_object_object_add(l_jobj_ticker, "declarations", l_jobj_decls);
            json_object_object_add(l_jobj_ticker, "updates", l_jobj_updates);
            json_object_object_add(l_jobj_tickers, l_token->ticker, l_jobj_ticker);
            l_token_num++;
        } else {
            l_jobj_decls = json_object_object_get(l_jobj_ticker, "declarations");
            l_jobj_updates = json_object_object_get(l_jobj_ticker, "updates");
        }
        int l_ret_code = l_datum_iter->ret_code;
        json_object* json_history_token = json_object_new_object();
        json_object_object_add(json_history_token, "status", json_object_new_string(l_ret_code ? "DECLINED" : "ACCEPTED"));
json_object_object_add(json_history_token, a_version == 1 ? "Ledger return code" : "ledger_ret_code", json_object_new_int(l_ret_code));
        switch (l_token->type) {
            case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_SIMPLE:
            case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_PUBLIC:
            case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_PRIVATE_DECL:
            case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_NATIVE_DECL:
            case DAP_CHAIN_DATUM_TOKEN_TYPE_DECL:
                dap_chain_datum_dump_json(a_json_arr_reply, json_history_token, l_datum, a_hash_out_type, a_chain->net_id, true, a_version);
                json_object_array_add(l_jobj_decls, json_history_token);
                break;
            case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_PRIVATE_UPDATE:
            case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_NATIVE_UPDATE:
            case DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE:
                dap_chain_datum_dump_json(a_json_arr_reply, json_history_token, l_datum, a_hash_out_type, a_chain->net_id, false, a_version);
                json_object_array_add(l_jobj_updates, json_history_token);
                break;
        }
        DAP_DELETE(l_token);
    }
    a_chain->callback_datum_iter_delete(l_datum_iter);
    if (a_token_num)
        *a_token_num = l_token_num;
    return l_jobj_tickers;
}

/**
 * @brief show all tokens in all chains in net
 *
 * @param a_chain
 * @param a_token_name
 * @param a_hash_out_type
 * @param a_token_num
 * @return char*
 */

static size_t dap_db_net_history_token_list(json_object* a_json_arr_reply, dap_chain_net_t * l_net, const char *a_token_name, const char *a_hash_out_type, json_object* a_obj_out, int a_version) {
    size_t l_token_num_total = 0;
    dap_chain_t *l_chain_cur;
    json_object* json_arr_obj_tx = json_object_new_array();    
    DL_FOREACH(l_net->pub.chains, l_chain_cur) {
        size_t l_token_num = 0;
        json_object* json_obj_tx = NULL;
        json_obj_tx = dap_db_chain_history_token_list(a_json_arr_reply, l_chain_cur, a_token_name, a_hash_out_type, &l_token_num, a_version);
        if(json_obj_tx)
            json_object_array_add(json_arr_obj_tx, json_obj_tx);
        l_token_num_total += l_token_num;
    }
    json_object_object_add(a_obj_out, a_version == 1 ? "TOKENS" : "tokens", json_arr_obj_tx);
    return l_token_num_total;
}

/**
 * @brief Recursively search for transaction chain path (simplified version)
 * @param a_ledger Ledger instance
 * @param a_current_hash Current transaction hash
 * @param a_target_hash Target hash to find
 * @param a_path_depth Current recursion depth
 * @param a_max_depth Maximum recursion depth
 * @param a_visited_hashes Set of visited hashes to prevent cycles
 * @param a_visited_count Number of visited hashes
 * @param a_json_chain JSON array to store the path
 * @param a_hash_out_type Output hash format
 * @return true if target found in this branch
 */
static bool s_ledger_trace_recursive(dap_ledger_t *a_ledger, 
                                    dap_chain_hash_fast_t *a_current_hash,
                                    dap_chain_hash_fast_t *a_target_hash,
                                    size_t a_path_depth,
                                    size_t a_max_depth,
                                    json_object *a_json_chain,
                                    const char *a_hash_out_type)
{
    static size_t l_target_depth = 0;
    // Check depth limit
    if (a_path_depth >= a_max_depth) {
        return false;
    }

    // Check if we found the target
    if (dap_hash_fast_compare(a_current_hash, a_target_hash)) {
        // Found target! Add it to chain
        json_object *l_json_tx = json_object_new_object();
        
        if (dap_strcmp(a_hash_out_type, "base58") == 0) {
            const char *l_hash_base58 = dap_enc_base58_encode_hash_to_str_static(a_current_hash);
            json_object_object_add(l_json_tx, "hash", json_object_new_string(l_hash_base58 ? l_hash_base58 : ""));
        } else {
            const char *l_hash_hex = dap_chain_hash_fast_to_str_static(a_current_hash);
            json_object_object_add(l_json_tx, "hash", json_object_new_string(l_hash_hex));
        }
        // Add previous output index information
        json_object_object_add(l_json_tx, "prev_out_idx", json_object_new_string("unavailable"));
        l_target_depth = a_path_depth;
        json_object_object_add(l_json_tx, "position", json_object_new_int(1));
        json_object_object_add(l_json_tx, "type", json_object_new_string("start"));
               
        json_object_array_add(a_json_chain, l_json_tx);
        
        return true;
    }
        
    // Get current transaction
    dap_chain_datum_tx_t *l_current_tx = dap_ledger_tx_find_by_hash(a_ledger, a_current_hash);
    if (!l_current_tx) {
        return false;
    }
           
    // Try each input until we find a path to target
    byte_t *l_item = NULL;
    size_t l_item_size = 0;
    int l_item_index = 0;
    TX_ITEM_ITER_TX_TYPE(l_item, TX_ITEM_TYPE_IN_ALL, l_item_size, l_item_index, l_current_tx) {

        dap_chain_hash_fast_t *l_tx_prev_hash = NULL;
        int l_tx_out_prev_idx = -1;
        
        switch (*l_item) {
            case TX_ITEM_TYPE_IN: {
                dap_chain_tx_in_t *l_tx_in = (dap_chain_tx_in_t *)l_item;
                l_tx_prev_hash = &l_tx_in->header.tx_prev_hash;
                l_tx_out_prev_idx = l_tx_in->header.tx_out_prev_idx;
            } break;
            case TX_ITEM_TYPE_IN_COND: {
                dap_chain_tx_in_cond_t *l_tx_in_cond = (dap_chain_tx_in_cond_t *)l_item;
                l_tx_prev_hash = &l_tx_in_cond->header.tx_prev_hash;
                l_tx_out_prev_idx = l_tx_in_cond->header.tx_out_prev_idx;
            } break;
            default:
                continue;
        }
        
        // Recursively search this branch
        bool l_found_in_branch = s_ledger_trace_recursive(a_ledger, l_tx_prev_hash, a_target_hash,
                                                            a_path_depth + 1, a_max_depth,
                                                            a_json_chain, a_hash_out_type);
        if (l_found_in_branch) {
            // Add current transaction to chain
            json_object *l_json_tx = json_object_new_object();
            if (dap_strcmp(a_hash_out_type, "base58") == 0) {
                const char *l_hash_base58 = dap_enc_base58_encode_hash_to_str_static(a_current_hash);
                json_object_object_add(l_json_tx, "hash", json_object_new_string(l_hash_base58 ? l_hash_base58 : ""));
            } else {
                const char *l_hash_hex = dap_chain_hash_fast_to_str_static(a_current_hash);
                json_object_object_add(l_json_tx, "hash", json_object_new_string(l_hash_hex));
            }
            // Add previous output index information
            json_object_object_add(l_json_tx, "prev_out_idx", json_object_new_int(l_tx_out_prev_idx));
            json_object_object_add(l_json_tx, "position", json_object_new_int(l_target_depth - a_path_depth + 1));
            if (a_path_depth == 0)
                json_object_object_add(l_json_tx, "type", json_object_new_string("target"));
            else
                json_object_object_add(l_json_tx, "type", json_object_new_string("intermediate"));
            
            // Found target in this branch - add current tx to chain and return success
            json_object_array_add(a_json_chain, l_json_tx);
            return true;
        }
    }
    
    return false;
}

/**
 * @brief Build transaction chain from a_hash_to to a_hash_from using simplified recursive traversal
 * @param a_ledger Ledger instance
 * @param a_hash_from Target hash
 * @param a_hash_to Starting hash
 * @param a_hash_out_type Output hash format
 * @param a_json_arr_reply JSON array for reply
 * @return 0 on success, error code on failure
 */
static int s_ledger_trace_chain(dap_ledger_t *a_ledger, dap_chain_hash_fast_t *a_hash_from, dap_chain_hash_fast_t *a_hash_to, 
                               const char *a_hash_out_type, size_t a_max_depth, json_object **a_json_arr_reply)
{
    // Validate input parameters
    if (!a_ledger || !a_hash_from || !a_hash_to || !a_json_arr_reply) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR, "Invalid input parameters");
        return DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR;
    }

    // Check if starting transaction exists
    dap_chain_datum_tx_t *l_start_tx = dap_ledger_tx_find_by_hash(a_ledger, a_hash_to);
    if (!l_start_tx) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_TX_HASH_ERR, 
                              "Starting transaction %s not found in ledger", dap_hash_fast_to_str_static(a_hash_to));
        return DAP_CHAIN_NODE_CLI_COM_LEDGER_TX_HASH_ERR;
    }

    // Check if target transaction exists
    dap_chain_datum_tx_t *l_target_tx = dap_ledger_tx_find_by_hash(a_ledger, a_hash_from);
    if (!l_target_tx) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_TX_HASH_ERR, 
                              "Target transaction %s not found in ledger", dap_hash_fast_to_str_static(a_hash_from));
        return DAP_CHAIN_NODE_CLI_COM_LEDGER_TX_HASH_ERR;
    }

    // Create result JSON object
    json_object *l_json_result = json_object_new_object();
    json_object *l_json_info = json_object_new_object();
    json_object *l_json_chain = json_object_new_array();

    // Add info about the trace
    json_object_object_add(l_json_info, "start_hash", json_object_new_string(dap_hash_fast_to_str_static(a_hash_from)));
    json_object_object_add(l_json_info, "target_hash", json_object_new_string(dap_hash_fast_to_str_static(a_hash_to)));
    json_object_object_add(l_json_info, "direction", json_object_new_string("backward"));
    json_object_object_add(l_json_info, "max_depth", json_object_new_int(a_max_depth));
    json_object_object_add(l_json_result, "trace_info", l_json_info);

    // Start recursive search
    bool l_found = s_ledger_trace_recursive(a_ledger, a_hash_to, a_hash_from,
                                           0, a_max_depth,
                                           l_json_chain, a_hash_out_type);

    // Add results to main JSON
    json_object_object_add(l_json_result, "chain", l_json_chain);
    json_object_object_add(l_json_result, "chain_length", json_object_new_int(json_object_array_length(l_json_chain)));
    json_object_object_add(l_json_result, "target_found", json_object_new_boolean(l_found));
    
    if (!l_found) {
        json_object_object_add(l_json_result, "status", 
                              json_object_new_string("No path found from start to target transaction"));
    } else {
        json_object_object_add(l_json_result, "status", 
                              json_object_new_string("Path found from start to target transaction"));
    }

    json_object_array_add(*a_json_arr_reply, l_json_result);
    return 0;
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
int com_ledger(int a_argc, char ** a_argv, void **reply, int a_version)
{
    json_object ** a_json_arr_reply = (json_object **) reply;
    enum { CMD_NONE, CMD_LIST, CMD_TX_INFO, CMD_TRACE, CMD_EVENT };
    int arg_index = 1;
    const char *l_net_str = NULL;
    const char *l_target_chain_str = NULL;
    const char *l_tx_hash_str = NULL;
    const char *l_hash_out_type = NULL;

    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR, "invalid parameter -H, valid values: -H <hex | base58>");
        return DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR;
    }

    //switch ledger params list | tx | info | trace
    int l_cmd = CMD_NONE;
    if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, arg_index + 1, "list", NULL)){
        l_cmd = CMD_LIST;
    } else if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, arg_index + 1, "info", NULL))
        l_cmd = CMD_TX_INFO;
    else if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, arg_index + 1, "trace", NULL))
        l_cmd = CMD_TRACE;
    else if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, arg_index + 1, "event", NULL))
        l_cmd = CMD_EVENT;


    bool l_is_all = dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-all", NULL);

    arg_index++;
    if (l_cmd == CMD_EVENT) {
        enum { SUBCMD_NONE, SUBCMD_LIST, SUBCMD_DUMP, SUBCMD_KEY, SUBCMD_CREATE };
        int l_subcmd = SUBCMD_NONE;
        
        if (dap_cli_server_cmd_find_option_val(a_argv, 2, 3, "list", NULL)) {
            l_subcmd = SUBCMD_LIST;
        } else if (dap_cli_server_cmd_find_option_val(a_argv, 2, 3, "dump", NULL)) {
            l_subcmd = SUBCMD_DUMP;
        } else if (dap_cli_server_cmd_find_option_val(a_argv, 2, 3, "key", NULL)) {
            l_subcmd = SUBCMD_KEY;
        } else if (dap_cli_server_cmd_find_option_val(a_argv, 2, 3, "create", NULL)) {
            l_subcmd = SUBCMD_CREATE;
        }
        
        if (l_subcmd == SUBCMD_NONE) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR, 
                                  "Subcommand 'event' requires subcommand 'list', 'dump', 'create' or 'key'");
            return DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR;
        }
        
        if (l_subcmd == SUBCMD_CREATE) {
            dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-net", &l_net_str);
            if (l_net_str == NULL) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_NET_PARAM_ERR, "Command requires key -net");
                return DAP_CHAIN_NODE_CLI_COM_LEDGER_NET_PARAM_ERR;
            }
            
            dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_NET_FIND_ERR, "Can't find net %s", l_net_str);
                return DAP_CHAIN_NODE_CLI_COM_LEDGER_NET_FIND_ERR;
            }
            
            // Получаем обязательные параметры для формирования транзакции-события
            const char *l_chain_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-chain", &l_chain_str);
            
            const char *l_wallet_name = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-w", &l_wallet_name);
            if (!l_wallet_name) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR, "Parameter -w is required to specify wallet");
                return DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR;
            }
            
            const char *l_service_key_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-service_key", &l_service_key_str);
            if (!l_service_key_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR, "Parameter -service_key is required");
                return DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR;
            }
            
            const char *l_group_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-group", &l_group_str);
            if (!l_group_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR, "Parameter -group is required");
                return DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR;
            }
            
            const char *l_event_type_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-event_type", &l_event_type_str);
            if (!l_event_type_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR, "Parameter -event_type is required");
                return DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR;
            }
            uint16_t l_event_type = (uint16_t)strtol(l_event_type_str, NULL, 10);
            
            const char *l_event_data_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-event_data", &l_event_data_str);
            
            const char *l_fee_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-fee", &l_fee_str);
            uint256_t l_fee = dap_chain_balance_scan(l_fee_str ? l_fee_str : "0");
            
            // Открываем кошелек и получаем из него ключ
            unsigned int l_wallet_stat = 0;
            const char *l_wallets_path = dap_chain_wallet_get_path(g_config);
            dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_name, l_wallets_path, &l_wallet_stat);
            if (!l_wallet) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR, "Can't open wallet %s, error %u", l_wallet_name, l_wallet_stat);
                return DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR;
            }
            
            dap_enc_key_t *l_key_from = dap_chain_wallet_get_key(l_wallet, 0);
            dap_chain_wallet_close(l_wallet);
            if (!l_key_from) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR, "Can't get key from wallet %s", l_wallet_name);
                return DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR;
            }
            
            dap_cert_t *l_service_key = dap_cert_find_by_name(l_service_key_str);
            if (!l_service_key) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR, "Can't find cert %s", l_service_key_str);
                return DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR;
            }
            
            // Получаем цепочку
            dap_chain_t *l_chain = l_chain_str ? dap_chain_net_get_chain_by_name(l_net, l_chain_str) :
                                   dap_chain_net_get_chain_by_chain_type(l_net, CHAIN_TYPE_TX);
            if (!l_chain) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR, 
                                      "Can't find chain %s in net %s", l_chain_str ? l_chain_str : "tx", l_net_str);
                return DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR;
            }
            
            // Подготавливаем данные события
            void *l_event_data = NULL;
            size_t l_event_data_size = 0;
            
            if (l_event_data_str) {
                l_event_data = DAP_NEW_SIZE(uint8_t, strlen(l_event_data_str) + 1);
                if (!l_event_data) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR, "Memory allocation error");
                    return DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR;
                }
                strcpy(l_event_data, l_event_data_str);
                l_event_data_size = strlen(l_event_data_str) + 1;
            }
            
            // Создаем транзакцию с событием
            char *l_tx_hash_str = dap_chain_mempool_tx_create_event(
                l_chain,
                l_key_from,
                l_service_key->enc_key,
                l_group_str,
                l_event_type,
                l_event_data,
                l_event_data_size,
                l_fee,
                l_hash_out_type
            );
            
            // Освобождаем ресурсы
            DAP_DEL_Z(l_event_data);
            
            if (l_tx_hash_str) {
                json_object *l_json_obj = json_object_new_object();
                json_object_object_add(l_json_obj, "status", json_object_new_string("success"));
                json_object_object_add(l_json_obj, "tx_hash", json_object_new_string(l_tx_hash_str));
                json_object_array_add(*a_json_arr_reply, l_json_obj);
                DAP_DEL_Z(l_tx_hash_str);
                return 0;
            } else {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR, 
                                      "Failed to create event transaction");
                return DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR;
            }
            
            return 0;
        }
        
        if (l_subcmd == SUBCMD_KEY) {
            enum { KEY_SUBCMD_NONE, KEY_SUBCMD_ADD, KEY_SUBCMD_REMOVE, KEY_SUBCMD_LIST };
            int l_key_subcmd = KEY_SUBCMD_NONE;
            
            if (dap_cli_server_cmd_find_option_val(a_argv, 3, 4, "add", NULL)) {
                l_key_subcmd = KEY_SUBCMD_ADD;
            } else if (dap_cli_server_cmd_find_option_val(a_argv, 3, 4, "remove", NULL)) {
                l_key_subcmd = KEY_SUBCMD_REMOVE;
            } else if (dap_cli_server_cmd_find_option_val(a_argv, 3, 4, "list", NULL)) {
                l_key_subcmd = KEY_SUBCMD_LIST;
            }
            
            if (l_key_subcmd == KEY_SUBCMD_NONE) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR,
                                      "Command 'event key' requires subcommand 'add', 'remove' or 'list'");
                return DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR;
            }
            
            dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-net", &l_net_str);
            if (l_net_str == NULL) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_NET_PARAM_ERR, "Command requires key -net");
                return DAP_CHAIN_NODE_CLI_COM_LEDGER_NET_PARAM_ERR;
            }
            
            dap_ledger_t *l_ledger = dap_ledger_by_net_name(l_net_str);
            if (l_ledger == NULL) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_LACK_ERR, "Can't get ledger for net %s", l_net_str);
                return DAP_CHAIN_NODE_CLI_COM_LEDGER_LACK_ERR;
            }
            
            if (l_key_subcmd == KEY_SUBCMD_LIST) {
                json_object* l_json_obj_out = json_object_new_object();
                json_object* l_json_array_keys = json_object_new_array();
                
                dap_list_t *l_list = dap_ledger_event_pkey_list(l_ledger);
                if (l_list) {
                    for (dap_list_t *l_item = l_list; l_item; l_item = l_item->next) {
                        dap_hash_fast_t *l_hash = (dap_hash_fast_t *)l_item->data;
                        const char *l_hash_str = dap_strcmp(l_hash_out_type, "hex") 
                                           ? dap_enc_base58_encode_hash_to_str_static(l_hash)
                                           : dap_chain_hash_fast_to_str_static(l_hash);
                        json_object_array_add(l_json_array_keys, json_object_new_string(l_hash_str));
                    }
                    
                    // Free the list and its elements
                    dap_list_free_full(l_list, free);
                }
                
                json_object_object_add(l_json_obj_out, "keys", l_json_array_keys);
                json_object_array_add(*a_json_arr_reply, l_json_obj_out);
                return 0;
            } else { // ADD or REMOVE key
                const char *l_pkey_hash_str = NULL;
                dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-hash", &l_pkey_hash_str);
                if (!l_pkey_hash_str) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR, 
                                          "Command requires parameter -hash for key hash");
                    return DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR;
                }
                
                dap_hash_fast_t l_pkey_hash = {};
                if (dap_chain_hash_fast_from_str(l_pkey_hash_str, &l_pkey_hash)) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_HASH_ERR, 
                                          "Invalid hash string format");
                    return DAP_CHAIN_NODE_CLI_COM_LEDGER_HASH_ERR;
                }
                
                int l_res = -1;
                const char *l_action = NULL;
                
                // Get certs for signing the decree
                const char *l_certs_str = NULL;
                dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-certs", &l_certs_str);
                if (!l_certs_str) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR,
                                        "Parameter -certs is required to sign the decree");
                    return DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR;
                }

                // Get certificates for signing
                char **l_certs_array = NULL;
                uint16_t l_certs_count = 0;
                dap_cert_t **l_certs = NULL;
                if (l_certs_str && strlen(l_certs_str) > 0) {
                    l_certs_array = dap_strsplit(l_certs_str, ",", -1);
                    if (!l_certs_array) {
                        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR,
                                            "Can't parse certs");
                        return DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR;
                    }
                    for(l_certs_count = 0; l_certs_array[l_certs_count]; l_certs_count++);
                    l_certs = DAP_NEW_SIZE(dap_cert_t*, sizeof(dap_cert_t*) * l_certs_count);
                    for(uint16_t i = 0; i < l_certs_count; i++) {
                        l_certs[i] = dap_cert_find_by_name(l_certs_array[i]);
                        if(!l_certs[i]){
                            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR,
                                                "Can't find cert \"%s\"", l_certs_array[i]);
                            DAP_DELETE(l_certs);
                            dap_strfreev(l_certs_array);
                            return DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR;
                        }
                    }
                } else {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR, 
                                            "Parameter -certs is required");
                    return DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR;
                }

                // Get or create decree chain
                dap_chain_t *l_chain = dap_chain_net_get_chain_by_chain_type(l_ledger->net, CHAIN_TYPE_DECREE);
                if (!l_chain) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_NO_DECREE_CHAIN,
                                            "Network %s doesn't have a decree chain", l_net_str);
                    DAP_DELETE(l_certs);
                    dap_strfreev(l_certs_array);
                    return DAP_CHAIN_NODE_CLI_COM_LEDGER_NO_DECREE_CHAIN;
                }
                dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-chain", &l_target_chain_str);
                dap_chain_t *l_target_chain = l_target_chain_str ? dap_chain_net_get_chain_by_name(l_ledger->net, l_target_chain_str) 
                                                                 : dap_chain_net_get_chain_by_chain_type(l_ledger->net, CHAIN_TYPE_TX);
                if (!l_target_chain) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_NO_ANCHOR_CHAIN,
                                            "Network %s doesn't have a chain %s", l_net_str, l_target_chain_str ? l_target_chain_str : "type tx");
                    return DAP_CHAIN_NODE_CLI_COM_LEDGER_NO_ANCHOR_CHAIN;
                }
                size_t l_tsd_size = sizeof(dap_tsd_t) + sizeof(dap_hash_fast_t); 
                // Create a decree
                size_t l_decree_size = sizeof(dap_chain_datum_decree_t) + l_tsd_size;
                dap_chain_datum_decree_t *l_decree = DAP_NEW_Z_SIZE(dap_chain_datum_decree_t, l_decree_size);
                l_decree->decree_version = DAP_CHAIN_DATUM_DECREE_VERSION;
                l_decree->header.ts_created = dap_time_now();
                l_decree->header.type = DAP_CHAIN_DATUM_DECREE_TYPE_COMMON;
                l_decree->header.common_decree_params.net_id = l_ledger->net->pub.id;
                l_decree->header.common_decree_params.chain_id = l_target_chain->id;
                l_decree->header.common_decree_params.cell_id = *dap_chain_net_get_cur_cell(l_ledger->net);
                // Set the subtype based on command
                l_decree->header.sub_type = l_key_subcmd == KEY_SUBCMD_ADD ? 
                                        DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_EVENT_PKEY_ADD : 
                                        DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_EVENT_PKEY_REMOVE;
                l_decree->header.data_size = l_tsd_size;
                l_decree->header.signs_size = 0;

                // Add TSD with key hash
                dap_tsd_write(l_decree->data_n_signs, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_HASH, &l_pkey_hash, sizeof(l_pkey_hash));

                // Sign the decree
                size_t l_total_signs_success = 0;
                l_decree = dap_chain_datum_decree_sign_in_cycle(l_certs, l_decree, l_certs_count, &l_total_signs_success);
                DAP_DELETE(l_certs);
                dap_strfreev(l_certs_array);

                if (!l_decree || l_total_signs_success == 0) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_SIGNING_FAILED,
                                        "Decree signing failed");
                    DAP_DELETE(l_decree);
                    return DAP_CHAIN_NODE_CLI_COM_LEDGER_SIGNING_FAILED;
                }

                // Create datum and add to mempool
                dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_DECREE,
                                                                    l_decree,
                                                                    sizeof(*l_decree) + l_decree->header.data_size +
                                                                    l_decree->header.signs_size);
                DAP_DELETE(l_decree);
                char *l_key_str_out = dap_chain_mempool_datum_add(l_datum, l_chain, l_hash_out_type);
                DAP_DELETE(l_datum);

                if (l_key_str_out) {
                    json_object *l_json_object = json_object_new_object();
                    json_object_object_add(l_json_object, "status", json_object_new_string("success"));
                    json_object_object_add(l_json_object, "action", json_object_new_string(l_key_subcmd == KEY_SUBCMD_ADD ? "add" : "remove"));
                    json_object_object_add(l_json_object, "decree_datum", json_object_new_string(l_key_str_out));
                    json_object_array_add(*a_json_arr_reply, l_json_object);
                    DAP_DELETE(l_key_str_out);
                    return 0;
                } else {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_MEMPOOL_FAILED, "Failed to add decree to mempool");
                    return DAP_CHAIN_NODE_CLI_COM_LEDGER_MEMPOOL_FAILED;
                }
            }
                
        } else if (l_subcmd == SUBCMD_LIST) {
            dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-net", &l_net_str);
            if (l_net_str == NULL) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_NET_PARAM_ERR, "Command requires key -net");
                return DAP_CHAIN_NODE_CLI_COM_LEDGER_NET_PARAM_ERR;
            }
            
            dap_ledger_t *l_ledger = dap_ledger_by_net_name(l_net_str);
            if (l_ledger == NULL) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_LACK_ERR, "Can't get ledger for net %s", l_net_str);
                return DAP_CHAIN_NODE_CLI_COM_LEDGER_LACK_ERR;
            }
            
            // Get list of all events
            const char *l_group_name = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-group", &l_group_name);
            
            json_object *l_json_obj_out = json_object_new_object();
            json_object *l_json_arr_events = json_object_new_array();
            
            // Get events for specific group or all events
            dap_list_t *l_events = dap_ledger_event_get_list(l_ledger, l_group_name);
            if (l_events) {
                for (dap_list_t *l_item = l_events; l_item; l_item = l_item->next) {
                    dap_chain_tx_event_t *l_event = (dap_chain_tx_event_t *)l_item->data;
                    json_object *l_json_event = json_object_new_object();
                    dap_chain_datum_tx_event_to_json(l_json_event, l_event, l_hash_out_type);
                    json_object_array_add(l_json_arr_events, l_json_event);
                }
                
                // Free the list and its elements
                dap_list_free_full(l_events, dap_chain_tx_event_delete);
            }

            json_object_object_add(l_json_obj_out, "events", l_json_arr_events);
            json_object_array_add(*a_json_arr_reply, l_json_obj_out);
            return 0;
        } else if (l_subcmd == SUBCMD_DUMP) {
            dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-net", &l_net_str);
            if (l_net_str == NULL) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_NET_PARAM_ERR, "Command requires key -net");
                return DAP_CHAIN_NODE_CLI_COM_LEDGER_NET_PARAM_ERR;
            }
            
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-hash", &l_tx_hash_str);
            if (!l_tx_hash_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR, 
                                      "Command 'event dump' requires parameter -hash for tx hash");
                return DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR;
            }
            
            dap_ledger_t *l_ledger = dap_ledger_by_net_name(l_net_str);
            if (l_ledger == NULL) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_LACK_ERR, "Can't get ledger for net %s", l_net_str);
                return DAP_CHAIN_NODE_CLI_COM_LEDGER_LACK_ERR;
            }
            
            dap_hash_fast_t l_tx_hash = {};
            if (dap_chain_hash_fast_from_str(l_tx_hash_str, &l_tx_hash)) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_HASH_ERR, 
                                      "Invalid hash string format");
                return DAP_CHAIN_NODE_CLI_COM_LEDGER_HASH_ERR;
            }
            
            dap_chain_tx_event_t *l_event = dap_ledger_event_find(l_ledger, &l_tx_hash);
            if (!l_event) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_LACK_ERR, 
                                      "Event not found for tx hash %s", l_tx_hash_str);
                return DAP_CHAIN_NODE_CLI_COM_LEDGER_LACK_ERR;
            }
            
            json_object *l_json_obj_out = json_object_new_object();
            dap_chain_datum_tx_event_to_json(l_json_obj_out, l_event, l_hash_out_type);
            json_object_array_add(*a_json_arr_reply, l_json_obj_out);
            dap_chain_tx_event_delete(l_event);
            return 0;
        }
    } else if (l_cmd == CMD_TRACE) {
        // Handle trace command
        const char *l_hash_from_str = NULL; // starting hash
        const char *l_hash_to_str = NULL;   // target hash
        const char *l_depth_str = NULL;     // recursion depth
        
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_str);
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-from", &l_hash_from_str);
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-to", &l_hash_to_str);
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-depth", &l_depth_str);
        
        // Parse recursion depth (default: 30)
        size_t l_max_depth = 30;
        if (l_depth_str) {
            char *l_endptr = NULL;
            unsigned long l_parsed_depth = strtoul(l_depth_str, &l_endptr, 10);
            if (*l_endptr != '\0' || l_parsed_depth == 0 || l_parsed_depth > 10000) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR, 
                                      "Invalid depth parameter. Must be a number between 1 and 10000");
                return DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR;
            }
            l_max_depth = (size_t)l_parsed_depth;
        }
        
        // Validate required parameters
        if (!l_hash_from_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR, 
                                  "Command 'trace' requires parameter -from");
            return DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR;
        }
        if (!l_hash_to_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR, 
                                  "Command 'trace' requires parameter -to");
            return DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR;
        }
        
        // Parse target hash (hash1)
        dap_chain_hash_fast_t l_hash_from = {};
        if (dap_chain_hash_fast_from_str(l_hash_from_str, &l_hash_from)) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_HASH_GET_ERR, 
                                "Can't parse target hash %s", l_hash_from_str);
            return DAP_CHAIN_NODE_CLI_COM_LEDGER_HASH_GET_ERR;
        }

        // Parse starting hash (hash2)
        dap_chain_hash_fast_t l_hash_to = {};
        if (dap_chain_hash_fast_from_str(l_hash_to_str, &l_hash_to)) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_HASH_GET_ERR, 
                                "Can't parse starting hash %s", l_hash_to_str);
            return DAP_CHAIN_NODE_CLI_COM_LEDGER_HASH_GET_ERR;
        }
        if (!l_net_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_NET_PARAM_ERR, 
                                  "Command 'trace' requires parameter -net");
            return DAP_CHAIN_NODE_CLI_COM_LEDGER_NET_PARAM_ERR;
        }
        // Get ledger
        dap_ledger_t *l_ledger = dap_ledger_by_net_name(l_net_str);
        if (!l_ledger) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_LACK_ERR, 
                                  "Can't get ledger for net %s", l_net_str);
            return DAP_CHAIN_NODE_CLI_COM_LEDGER_LACK_ERR;
        }

        // Execute trace
        return s_ledger_trace_chain(l_ledger, &l_hash_from, &l_hash_to, l_hash_out_type, l_max_depth, a_json_arr_reply);
        
    } else if (l_cmd == CMD_LIST) {
        enum {SUBCMD_NONE, SUBCMD_LIST_COIN, SUB_CMD_LIST_LEDGER_THRESHOLD, SUB_CMD_LIST_LEDGER_BALANCE, SUB_CMD_LIST_LEDGER_THRESHOLD_WITH_HASH};
        int l_sub_cmd = SUBCMD_NONE;
        dap_chain_hash_fast_t l_tx_threshold_hash = {};
        const char *l_limit_str = NULL;
        const char *l_offset_str = NULL;
        const char *l_head_str = NULL;
        if (dap_cli_server_cmd_find_option_val(a_argv, 2, 3, "coins", NULL ))
            l_sub_cmd = SUBCMD_LIST_COIN;
        if (dap_cli_server_cmd_find_option_val(a_argv, 2, 3, "balance", NULL ))
            l_sub_cmd = SUB_CMD_LIST_LEDGER_BALANCE;
        if (dap_cli_server_cmd_find_option_val(a_argv, 2, a_argc, "threshold", NULL)){
            l_sub_cmd = SUB_CMD_LIST_LEDGER_THRESHOLD;
            const char* l_tx_threshold_hash_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, 3, a_argc, "-hash", &l_tx_threshold_hash_str);
            if (l_tx_threshold_hash_str){
                l_sub_cmd = SUB_CMD_LIST_LEDGER_THRESHOLD_WITH_HASH;
                if (dap_chain_hash_fast_from_str(l_tx_threshold_hash_str, &l_tx_threshold_hash)){
                    l_tx_hash_str = NULL;
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_TRESHOLD_ERR, "tx threshold hash not recognized");
                    return DAP_CHAIN_NODE_CLI_COM_LEDGER_TRESHOLD_ERR;
                }
            }
        }
        if (l_sub_cmd == SUBCMD_NONE) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR, "Command 'list' requires subcommands 'coins' or 'threshold'");
            return DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR;
        }
        dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-net", &l_net_str);
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-limit", &l_limit_str);
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-offset", &l_offset_str);
        bool l_head = dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-head", &l_head_str) ? true : false;
        size_t l_limit = l_limit_str ? strtoul(l_limit_str, NULL, 10) : 0;
        size_t l_offset = l_offset_str ? strtoul(l_offset_str, NULL, 10) : 0;
        if (l_net_str == NULL){
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_NET_PARAM_ERR, "Command 'list' requires key -net");
            return DAP_CHAIN_NODE_CLI_COM_LEDGER_NET_PARAM_ERR;
        }
        dap_ledger_t *l_ledger = dap_ledger_by_net_name(l_net_str);
        if (l_ledger == NULL){
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_LACK_ERR, "Can't get ledger for net %s", l_net_str);
            return DAP_CHAIN_NODE_CLI_COM_LEDGER_LACK_ERR;
        }
        if (l_sub_cmd == SUB_CMD_LIST_LEDGER_THRESHOLD) {
            json_object* json_obj_out = dap_ledger_threshold_info(l_ledger, l_limit, l_offset, NULL, l_head, a_version);
            if (json_obj_out){
                json_object_array_add(*a_json_arr_reply, json_obj_out);
            }
            return 0;
        }
        if (l_sub_cmd == SUB_CMD_LIST_LEDGER_THRESHOLD_WITH_HASH) {
            json_object *json_obj_out = dap_ledger_threshold_info(l_ledger, 0, 0, &l_tx_threshold_hash, l_head, a_version);
            if (json_obj_out){
                json_object_array_add(*a_json_arr_reply, json_obj_out);
            }
            return 0;
        }
        if (l_sub_cmd == SUB_CMD_LIST_LEDGER_BALANCE) {
            json_object *json_obj_out = dap_ledger_balance_info(l_ledger, l_limit, l_offset, l_head, a_version);
            if (json_obj_out){
                json_object_array_add(*a_json_arr_reply, json_obj_out);
            }
            return 0;
        }
        json_object *json_obj_datum = dap_ledger_token_info(l_ledger, l_limit, l_offset, a_version);

        if (json_obj_datum) {
            json_object_array_add(*a_json_arr_reply, json_obj_datum);
        }
        return 0;
    } else if (l_cmd == CMD_TX_INFO) {
        //GET hash
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-hash", &l_tx_hash_str);
        //get net
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_str);
        //get search type
        bool l_unspent_flag = dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-unspent", NULL);
        bool l_need_sign  = dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-need_sign", NULL);
        //check input
        if (l_tx_hash_str == NULL){
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR, "Subcommand 'info' requires key -hash");
            return DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR;
        }
        if (l_net_str == NULL){
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_NET_PARAM_ERR, "Subcommand 'info' requires key -net");
            return DAP_CHAIN_NODE_CLI_COM_LEDGER_NET_PARAM_ERR;
        }
        dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
        if (!l_net) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_NET_FIND_ERR, "Can't find net %s", l_net_str);
            return DAP_CHAIN_NODE_CLI_COM_LEDGER_NET_FIND_ERR;
        }
        dap_chain_hash_fast_t *l_tx_hash = DAP_NEW(dap_chain_hash_fast_t);
        if (dap_chain_hash_fast_from_str(l_tx_hash_str, l_tx_hash)) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_HASH_GET_ERR, "Can't get hash_fast from %s, check that the hash is correct", l_tx_hash_str);
            DAP_DEL_Z(l_tx_hash);
            return DAP_CHAIN_NODE_CLI_COM_LEDGER_HASH_GET_ERR;
        }
        dap_chain_datum_tx_t *l_datum_tx = dap_chain_net_get_tx_by_hash(l_net, l_tx_hash,
                                                                        l_unspent_flag ? TX_SEARCH_TYPE_NET_UNSPENT : TX_SEARCH_TYPE_NET);
        if (l_datum_tx == NULL) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_TX_HASH_ERR, "Can't find datum for transaction hash %s in chains", l_tx_hash_str);
            DAP_DEL_Z(l_tx_hash);
            return DAP_CHAIN_NODE_CLI_COM_LEDGER_TX_HASH_ERR;
        }
        json_object* json_datum = json_object_new_object();
        if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-tx_to_json", NULL)) {
            const char *l_ticker = dap_ledger_tx_get_token_ticker_by_hash(l_net->pub.ledger, l_tx_hash);
            json_object_object_add(json_datum, "token_ticker", json_object_new_string(l_ticker));
            bool l_all_outs_unspent = true;
            byte_t *l_item; size_t l_size; int index, l_out_idx = -1;
            json_object* json_arr_items = json_object_new_array();
            TX_ITEM_ITER_TX_TYPE(l_item, TX_ITEM_TYPE_OUT_ALL, l_size, index, l_datum_tx) {
                dap_hash_fast_t l_spender = { };
                ++l_out_idx;
                if ( dap_ledger_tx_hash_is_used_out_item(l_net->pub.ledger, l_tx_hash, l_out_idx, NULL) ) {
                    l_all_outs_unspent = false;
                    char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE] = { '\0' };
                    dap_hash_fast_to_str(&l_spender, l_hash_str, sizeof(l_hash_str));
                    json_object * l_json_obj_datum = json_object_new_object();
                    json_object_object_add(l_json_obj_datum, "out_idx", json_object_new_int(l_out_idx));
                    json_object_object_add(l_json_obj_datum, "spent_by_tx", json_object_new_string(l_hash_str));
                    json_object_array_add(json_arr_items, l_json_obj_datum);
                }
            }
            json_object_object_add(json_datum, "all_outs_unspent", json_object_new_boolean(l_all_outs_unspent));
            if (l_all_outs_unspent) {
                json_object_put(json_arr_items);
            } else {
                json_object_object_add(json_datum, "spent_outs", json_arr_items);
            }
            dap_chain_net_tx_to_json(l_datum_tx, json_datum);
            if (!json_object_object_length(json_datum)) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_TX_TO_JSON_ERR, "Can't find transaction hash %s in ledger", l_tx_hash_str);
                json_object_put(json_datum);
                DAP_DELETE(l_tx_hash);
                return DAP_CHAIN_NODE_CLI_COM_LEDGER_TX_TO_JSON_ERR;
            }
            json_object_array_add(*a_json_arr_reply, json_datum);
            DAP_DELETE(l_tx_hash);
            return 0;
        }

        if (!s_dap_chain_datum_tx_out_data(*a_json_arr_reply,l_datum_tx, l_net->pub.ledger, json_datum, l_hash_out_type, l_tx_hash, a_version)){
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_TX_HASH_ERR, "Can't find transaction hash %s in ledger", l_tx_hash_str);
            json_object_put(json_datum);
            DAP_DEL_Z(l_tx_hash);
            return DAP_CHAIN_NODE_CLI_COM_LEDGER_TX_HASH_ERR;
        }
        if (l_need_sign) {
            byte_t *item; size_t l_size;
            TX_ITEM_ITER_TX(item, l_size, l_datum_tx) {
                if (*item == TX_ITEM_TYPE_SIG) {
                    dap_sign_t *l_sign = dap_chain_datum_tx_item_sig_get_sign((dap_chain_tx_sig_t*)item);
                    char *l_sign_b64 = DAP_NEW_Z_SIZE(char, DAP_ENC_BASE64_ENCODE_SIZE(dap_sign_get_size(l_sign)) + 1);
                    size_t l_sign_size = dap_sign_get_size(l_sign);
                    dap_enc_base64_encode(l_sign, l_sign_size, l_sign_b64, DAP_ENC_DATA_TYPE_B64_URLSAFE);
                    
                    json_object *json_items = json_object_object_get(json_datum, "items");
                    if (json_items && json_object_is_type(json_items, json_type_array)) {
                        int array_len = json_object_array_length(json_items);
                        for (int i = 0; i < array_len; i++) {
                            json_object *item = json_object_array_get_idx(json_items, i);
                            const char *item_type = json_object_get_string(json_object_object_get(item, "type"));
                            if (item_type && strcmp(item_type, "sig_dil") == 0) {
                                json_object_object_add(item, "sig_b64", json_object_new_string(l_sign_b64));
                                json_object_object_add(item, "sig_b64_size", json_object_new_uint64(l_sign_size));
                            }
                        }
                    }
                }
            }
        }
        DAP_DELETE(l_tx_hash);

        if (json_datum){
            json_object_array_add(*a_json_arr_reply, json_datum);
        }        
    } else {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR, "Command 'ledger' requires parameter 'list', 'info', 'trace', or 'event'");
        return DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR;
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
int com_token(int a_argc, char ** a_argv, void **a_str_reply, int a_version)
{
    json_object **a_json_arr_reply = (json_object **)a_str_reply;
    enum { CMD_NONE, CMD_LIST, CMD_INFO, CMD_TX };
    int arg_index = 1;
    const char *l_net_str = NULL;
    dap_chain_net_t * l_net = NULL;

    const char * l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    if (!l_hash_out_type)
        l_hash_out_type = "hex";
    if (dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_PARAM_ERR, "invalid parameter -H, valid values: -H <hex | base58>");
        return -DAP_CHAIN_NODE_CLI_COM_TOKEN_PARAM_ERR;
    }

    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_str);
    // Select chain network
    if(!l_net_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_PARAM_ERR, "command requires parameter '-net'");
        return -DAP_CHAIN_NODE_CLI_COM_TOKEN_PARAM_ERR;
    } else {
        if((l_net = dap_chain_net_by_name(l_net_str)) == NULL) { // Can't find such network
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_PARAM_ERR,
                    "command requires parameter '-net' to be valid chain network name");            
            return -DAP_CHAIN_NODE_CLI_COM_TOKEN_PARAM_ERR;
        }
    }

    int l_cmd = CMD_NONE;
    if (dap_cli_server_cmd_find_option_val(a_argv, 1, 2, "list", NULL))
        l_cmd = CMD_LIST;
    else if (dap_cli_server_cmd_find_option_val(a_argv, 1, 2, "info", NULL))
        l_cmd = CMD_INFO;
    else if (dap_cli_server_cmd_find_option_val(a_argv, 1, 2, "tx", NULL))
            l_cmd = CMD_TX;
    // token list
    if(l_cmd == CMD_LIST) {
        json_object* json_obj_tx = json_object_new_object();
        size_t l_total_all_token = dap_db_net_history_token_list(*a_json_arr_reply, l_net, NULL, l_hash_out_type, json_obj_tx, a_version);

        json_object_object_length(json_obj_tx);
        json_object_object_add(json_obj_tx, "tokens", json_object_new_uint64(l_total_all_token));
        json_object_array_add(*a_json_arr_reply, json_obj_tx);
        return 0;
    }
    // token info
    else if(l_cmd == CMD_INFO) {
        const char *l_token_name_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-name", &l_token_name_str);
        if(!l_token_name_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_PARAM_ERR, "command requires parameter '-name' <token name>");
            return -DAP_CHAIN_NODE_CLI_COM_TOKEN_PARAM_ERR;
        }
        json_object *json_obj_tx = json_object_new_object();
        if (!dap_db_net_history_token_list(*a_json_arr_reply, l_net, l_token_name_str, l_hash_out_type, json_obj_tx, a_version)) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_FOUND_ERR, "token '%s' not found\n", l_token_name_str);\
            return -DAP_CHAIN_NODE_CLI_COM_TOKEN_UNKNOWN;
        }
        json_object_array_add(*a_json_arr_reply, json_obj_tx);
        return DAP_CHAIN_NODE_CLI_COM_TOKEN_OK;
    }
    // command tx history
    else if(l_cmd == CMD_TX) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_UNKNOWN, 
            "The cellframe-node-cli token tx command is deprecated and no longer supported.\n");
        
        return DAP_CHAIN_NODE_CLI_COM_TOKEN_UNKNOWN;
#if 0
        dap_chain_tx_hash_processed_ht_t *l_list_tx_hash_processd = NULL;
        enum { SUBCMD_TX_NONE, SUBCMD_TX_ALL, SUBCMD_TX_ADDR };
        // find subcommand
        int l_subcmd = CMD_NONE;
        const char *l_addr_base58_str = NULL;
        const char *l_wallet_name = NULL;
        if(dap_cli_server_cmd_find_option_val(a_argv, 2, a_argc, "all", NULL))
            l_subcmd = SUBCMD_TX_ALL;
        else if(dap_cli_server_cmd_find_option_val(a_argv, 2, a_argc, "-addr", &l_addr_base58_str))
            l_subcmd = SUBCMD_TX_ADDR;
        else if(dap_cli_server_cmd_find_option_val(a_argv, 2, a_argc, "-w", &l_wallet_name))
            l_subcmd = SUBCMD_TX_ADDR;

        const char *l_token_name_str = NULL;
        const char *l_page_start_str = NULL;
        const char *l_page_size_str = NULL;
        const char *l_page_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-name", &l_token_name_str);
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-page_start", &l_page_start_str);
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-page_size", &l_page_size_str);
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-page", &l_page_str);
        if(!l_token_name_str) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "command requires parameter '-name' <token name>");
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
                    dap_ledger_t *l_ledger = dap_ledger_by_net_name(l_net_str);
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
            s_dap_chain_tx_hash_processed_ht_free(&l_list_tx_hash_processd);
            dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_str_out->str);
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
                    dap_chain_addr_t *l_addr_tmp = (dap_chain_addr_t *) dap_chain_wallet_get_addr(l_wallet,
                                                                                                  l_net->pub.id);
                    l_addr_base58 = DAP_NEW_SIZE(dap_chain_addr_t, sizeof(dap_chain_addr_t));
                    memcpy(l_addr_base58, l_addr_tmp, sizeof(dap_chain_addr_t));
                    dap_chain_wallet_close(l_wallet);
                    char *ffl_addr_base58 = dap_chain_addr_to_str_static(l_addr_base58);
                    ffl_addr_base58 = 0;
                }
                else {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "wallet '%s' not found", l_wallet_name);
                    return -2;
                }
            }
            if(!l_addr_base58) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "address not recognized");
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
            dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_str_out->str);
            dap_string_free(l_str_out, true);
            DAP_DELETE(l_addr_base58);
            return 0;

        }
        else{
            dap_cli_server_cmd_set_reply_text(a_str_reply, "not found parameter '-all', '-wallet' or '-addr'");
            return -1;
        }
#endif
    }

    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_UNKNOWN, "unknown command code %d", l_cmd);
    return -DAP_CHAIN_NODE_CLI_COM_TOKEN_UNKNOWN;
}

/**
 * @brief Create transaction from json file
 * com_tx_create command
 * @param argc
 * @param argv
 * @param arg_func
 * @param str_reply
 * @return int
 */
int com_tx_create_json(int a_argc, char ** a_argv, void **reply, UNUSED_ARG int a_version)
{
    json_object **a_json_arr_reply = (json_object**)reply;
    int l_arg_index = 1;
    const char *l_net_name = NULL; // optional parameter
    const char *l_chain_name = NULL; // optional parameter
    const char *l_json_file_path = NULL;
    const char *l_json_str = NULL;

    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_name); // optional parameter
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-chain", &l_chain_name); // optional parameter
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-json", &l_json_file_path);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-tx_obj", &l_json_str);

    if(!l_json_file_path  && !l_json_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NET_TX_CREATE_JSON_REQUIRE_PARAMETER_JSON,
                               "Command requires one of parameters '-json <json file path>' or -tx_obj <string>'");
        return DAP_CHAIN_NET_TX_CREATE_JSON_REQUIRE_PARAMETER_JSON;
    }
    // Open json file
    struct json_object *l_json = NULL;
    if (l_json_file_path){
        l_json = json_object_from_file(l_json_file_path);
        if(!l_json) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NET_TX_CREATE_JSON_CAN_NOT_OPEN_JSON_FILE,
                                "Can't open json file: %s", json_util_get_last_err());
            return DAP_CHAIN_NET_TX_CREATE_JSON_CAN_NOT_OPEN_JSON_FILE;
        }
    } else if (l_json_str) {
        l_json = json_tokener_parse(l_json_str);
        if(!l_json) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NET_TX_CREATE_JSON_CAN_NOT_OPEN_JSON_FILE,
                                "Can't parse input JSON-string", json_util_get_last_err());
            return DAP_CHAIN_NET_TX_CREATE_JSON_CAN_NOT_OPEN_JSON_FILE;
        }
    }
    if(!json_object_is_type(l_json, json_type_object)) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NET_TX_CREATE_JSON_WRONG_JSON_FORMAT, "Wrong json format");
        json_object_put(l_json);
        return DAP_CHAIN_NET_TX_CREATE_JSON_WRONG_JSON_FORMAT;
    }


    // Read network from json file
    if(!l_net_name) {
        struct json_object *l_json_net = json_object_object_get(l_json, "net");
        if(l_json_net && json_object_is_type(l_json_net, json_type_string)) {
            l_net_name = json_object_get_string(l_json_net);
        }
        if(!l_net_name) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NET_TX_CREATE_JSON_REQUIRE_PARAMETER_NET,
                                   "Command requires parameter '-net' or set net in the json file");
            json_object_put(l_json);
            return DAP_CHAIN_NET_TX_CREATE_JSON_REQUIRE_PARAMETER_NET;
        }
    }
    dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_name);
    if(!l_net) {
        dap_json_rpc_error_add(*a_json_arr_reply,
                               DAP_CHAIN_NET_TX_CREATE_JSON_NOT_FOUNT_NET_BY_NAME,
                               "Not found net by name '%s'", l_net_name);
        json_object_put(l_json);
        return DAP_CHAIN_NET_TX_CREATE_JSON_NOT_FOUNT_NET_BY_NAME;
    }

    // Read chain from json file
    if(!l_chain_name) {
        struct json_object *l_json_chain = json_object_object_get(l_json, "chain");
        if(l_json_chain && json_object_is_type(l_json_chain, json_type_string)) {
            l_chain_name = json_object_get_string(l_json_chain);
        }
    }
    dap_chain_t *l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_name);
    if(!l_chain) {
        l_chain = dap_chain_net_get_chain_by_chain_type(l_net, CHAIN_TYPE_TX);
    }
    if(!l_chain) {
        dap_json_rpc_error_add(*a_json_arr_reply,
                               DAP_CHAIN_NET_TX_CREATE_JSON_NOT_FOUNT_CHAIN_BY_NAME,
                               "Chain name '%s' not found, try use parameter '-chain' or set chain in the json file", l_chain_name);
        json_object_put(l_json);
        return DAP_CHAIN_NET_TX_CREATE_JSON_NOT_FOUNT_CHAIN_BY_NAME;
    }


    // Read items from json file
    json_object *l_jobj_errors = json_object_new_array();
    size_t l_items_ready = 0, l_items_count = 0;
    dap_chain_datum_tx_t *l_tx = NULL;
    int l_ret = 0;
    if((l_ret = dap_chain_net_tx_create_by_json(l_json, l_net, l_jobj_errors, &l_tx, &l_items_count, &l_items_ready)) != DAP_CHAIN_NET_TX_CREATE_JSON_OK) {
        dap_json_rpc_error_add(*a_json_arr_reply, l_ret,
                               "Can't create transaction from json file");
        return l_ret;
    }
    json_object *l_jobj_ret = json_object_new_object();

    if(l_items_ready < l_items_count) {
        json_object *l_tx_create = json_object_new_boolean(false);
        json_object *l_jobj_valid_items = json_object_new_uint64(l_items_ready);
        json_object *l_jobj_total_items = json_object_new_uint64(l_items_count);
        json_object_object_add(l_jobj_ret, "tx_create", l_tx_create);
        json_object_object_add(l_jobj_ret, "valid_items", l_jobj_valid_items);
        json_object_object_add(l_jobj_ret, "total_items", l_jobj_total_items);
        json_object_object_add(l_jobj_ret, "errors", l_jobj_errors);
        json_object_array_add(*a_json_arr_reply, l_jobj_ret);
        DAP_DELETE(l_tx);
        return DAP_CHAIN_NET_TX_CREATE_JSON_INVALID_ITEMS;
    }
    json_object_put(l_jobj_errors);

    // Pack transaction into the datum
    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
    dap_chain_datum_t *l_datum_tx = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, l_tx_size);
    size_t l_datum_tx_size = dap_chain_datum_size(l_datum_tx);
    DAP_DELETE(l_tx);

    // Add transaction to mempool
    char *l_tx_hash_str = dap_get_data_hash_str(l_datum_tx->data, l_datum_tx->header.data_size).s;
    dap_chain_hash_fast_t l_hf_tx = {0};
    dap_chain_hash_fast_from_str(l_tx_hash_str, &l_hf_tx);
    int rc = -1;
    if ((rc = dap_ledger_tx_add_check(l_net->pub.ledger, (dap_chain_datum_tx_t*)l_datum_tx->data, l_tx_size, &l_hf_tx))) {
        json_object *l_jobj_tx_create = json_object_new_boolean(false);
        json_object *l_jobj_hash = json_object_new_string(l_tx_hash_str);
        json_object *l_jobj_total_items = json_object_new_uint64(l_items_count);
        json_object *l_jobj_ledger_ret_code = json_object_new_object();
        json_object_object_add(l_jobj_ledger_ret_code, "code", json_object_new_int(rc));
        json_object_object_add(l_jobj_ledger_ret_code, "message",
                               json_object_new_string(dap_chain_net_verify_datum_err_code_to_str(l_datum_tx, rc)));
        json_object_object_add(l_jobj_ret, "tx_create", l_jobj_tx_create);
        json_object_object_add(l_jobj_ret, "hash", l_jobj_hash);
        json_object_object_add(l_jobj_ret, "ledger_code", l_jobj_ledger_ret_code);
        json_object_object_add(l_jobj_ret, "total_items", l_jobj_total_items);
        json_object_array_add(*a_json_arr_reply, l_jobj_ret);
        DAP_DEL_Z(l_datum_tx);
        return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CAN_NOT_CREATE_TRANSACTION;
    }

    char *l_gdb_group_mempool_base_tx = dap_chain_mempool_group_new(l_chain);// get group name for mempool
    bool l_placed = !dap_global_db_set(l_gdb_group_mempool_base_tx, l_tx_hash_str, l_datum_tx, l_datum_tx_size, false, NULL, NULL);

    DAP_DEL_Z(l_datum_tx);
    DAP_DELETE(l_gdb_group_mempool_base_tx);
    if(!l_placed) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NET_TX_CREATE_JSON_CAN_NOT_ADD_TRANSACTION_TO_MEMPOOL,
                               "Can't add transaction to mempool");
        return DAP_CHAIN_NET_TX_CREATE_JSON_CAN_NOT_ADD_TRANSACTION_TO_MEMPOOL;
    }
    // Completed successfully
    json_object *l_jobj_tx_create = json_object_new_boolean(true);
    json_object *l_jobj_hash = json_object_new_string(l_tx_hash_str);
    json_object *l_jobj_total_items = json_object_new_uint64(l_items_count);
    json_object_object_add(l_jobj_ret, "tx_create", l_jobj_tx_create);
    json_object_object_add(l_jobj_ret, "hash", l_jobj_hash);
    json_object_object_add(l_jobj_ret, "total_items", l_jobj_total_items);
    json_object_array_add(*a_json_arr_reply, l_jobj_ret);
    return DAP_CHAIN_NET_TX_CREATE_JSON_OK;
}

/**
 * @brief Create transaction
 * com_tx_create command
 * @param argc
 * @param argv
 * @param arg_func
 * @param str_reply
 * @return int
 */
int com_tx_create(int a_argc, char **a_argv, void **a_json_arr_reply, UNUSED_ARG int a_version)
{
    int arg_index = 1;
//    int cmd_num = 1;
//    const char *value_str = NULL;
    const char *addr_base58_to = NULL;
    const char * l_fee_str = NULL;
    const char * l_value_str = NULL;
    const char * l_from_wallet_name = NULL;
    const char * l_wallet_fee_name = NULL;
    const char * l_token_ticker = NULL;
    const char * l_net_name = NULL;
    const char * l_chain_name = NULL;
    const char * l_emission_chain_name = NULL;
    const char * l_tx_num_str = NULL;
    const char *l_emission_hash_str = NULL;
    const char *l_cert_str = NULL;
    const char *l_time_str = NULL;
    dap_cert_t *l_cert = NULL;
    dap_enc_key_t *l_priv_key = NULL;
    dap_chain_hash_fast_t l_emission_hash = {};
    size_t l_tx_num = 0;
    dap_chain_wallet_t * l_wallet_fee = NULL;

    const char * l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_HASH_INVALID, "Invalid parameter -H, valid values: -H <hex | base58>");
        return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_HASH_INVALID;
    }

    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_name);
    dap_chain_net_t * l_net = dap_chain_net_by_name(l_net_name);
    if (l_net == NULL) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_NET_NOT_FOUND, "not found net by name '%s'", l_net_name);
        return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_NET_NOT_FOUND;
    }

    uint256_t *l_value = NULL;
    uint256_t l_value_fee = {};
    const dap_chain_addr_t **l_addr_to = NULL;
    size_t l_addr_el_count = 0;
    size_t l_value_el_count = 0;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-from_wallet", &l_from_wallet_name);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-wallet_fee", &l_wallet_fee_name);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-from_emission", &l_emission_hash_str);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-chain_emission", &l_emission_chain_name);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-chain", &l_chain_name);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-tx_num", &l_tx_num_str);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-cert", &l_cert_str);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-lock_before", &l_time_str);

    if(l_tx_num_str)
        l_tx_num = strtoul(l_tx_num_str, NULL, 10);

    // Validator's fee
    if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-fee", &l_fee_str)) {
        if (!l_fee_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_FEE, "tx_create requires parameter '-fee'");
            return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_FEE;
        }
        l_value_fee = dap_chain_balance_scan(l_fee_str);
    }
    if (IS_ZERO_256(l_value_fee) && (!l_emission_hash_str || (l_fee_str && strcmp(l_fee_str, "0")))) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_FEE_IS_UINT256, "tx_create requires parameter '-fee' to be valid uint256");
        return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_FEE_IS_UINT256;
    }

    if((!l_from_wallet_name && !l_emission_hash_str)||(l_from_wallet_name && l_emission_hash_str)) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_FROM_WALLET_OR_FROM_EMISSION, "tx_create requires one of parameters '-from_wallet' or '-from_emission'");
        return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_FROM_WALLET_OR_FROM_EMISSION;
    }

    const char *c_wallets_path = dap_chain_wallet_get_path(g_config);

    dap_chain_t *l_chain = NULL;
    if (l_chain_name) {
        l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_name);
    } else {
        l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net,CHAIN_TYPE_TX);
    }

    if(!l_chain) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_NOT_FOUND_CHAIN,
                               "not found chain name '%s', try use parameter '-chain' or set default datum type in chain configuration file",
                l_chain_name);
        return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_NOT_FOUND_CHAIN;
    }

    dap_chain_t *l_emission_chain = NULL;
    if (l_emission_hash_str) {
        if (dap_chain_hash_fast_from_str(l_emission_hash_str, &l_emission_hash)) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_FROM_EMISSION,
                                   "tx_create requires parameter '-from_emission' "
                                   "to be valid string containing hash in hex or base58 format");
            return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_FROM_EMISSION;
        }
        if (l_emission_chain_name) {
            l_emission_chain = dap_chain_net_get_chain_by_name(l_net, l_emission_chain_name);
        } else {
            l_emission_chain = dap_chain_net_get_default_chain_by_chain_type(l_net,CHAIN_TYPE_EMISSION);
        }
        if (!l_emission_chain) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_FROM_CHAIN_EMISSION,
                                   "tx_create requires parameter '-chain_emission' "
                                   "to be a valid chain name or set default datum type in chain configuration file");
            return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_FROM_CHAIN_EMISSION;
        }

        if (l_wallet_fee_name){
            l_wallet_fee = dap_chain_wallet_open(l_wallet_fee_name, c_wallets_path, NULL);
            if (!l_wallet_fee) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_WALLET_FEE,
                                       "Wallet %s does not exist", l_wallet_fee_name);
                return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_WALLET_FEE;
            }
            l_priv_key = dap_chain_wallet_get_key(l_wallet_fee, 0);
        } else if (l_cert_str) {
            l_cert = dap_cert_find_by_name(l_cert_str);
            if (!l_cert) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CERT_IS_INVALID, "Certificate %s is invalid", l_cert_str);
                return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CERT_IS_INVALID;
            }
            l_priv_key = l_cert->enc_key;
        } else {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_CERT_OR_WALLET_FEE,
                                              "tx_create requires parameter '-cert' or '-wallet_fee' for create base tx for emission");
            return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_CERT_OR_WALLET_FEE;
        }
    } else {
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-token", &l_token_ticker);
        if (!l_token_ticker) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_TOKEN, "tx_create requires parameter '-token'");
            return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_TOKEN;
        }
        if (!dap_ledger_token_ticker_check(l_net->pub.ledger, l_token_ticker)) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_TOKEN_NOT_DECLARATED_IN_NET,
                                   "Ticker '%s' is not declared on network '%s'.", l_token_ticker, l_net_name);
            return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_TOKEN_NOT_DECLARATED_IN_NET;
        }
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-to_addr", &addr_base58_to);
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-value", &l_value_str);
        if (!addr_base58_to) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_TO_ADDR, "tx_create requires parameter '-to_addr'");
            return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_TO_ADDR;
        }
        if (!l_value_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_VALUE_OR_INVALID_FORMAT_VALUE, "tx_create requires parameter '-value' to be valid uint256 value");
            return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_VALUE_OR_INVALID_FORMAT_VALUE;
        }
        l_addr_el_count = dap_str_symbol_count(addr_base58_to, ',') + 1;
        l_value_el_count = dap_str_symbol_count(l_value_str, ',') + 1;

        if (l_addr_el_count != l_value_el_count) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_VALUE_OR_INVALID_FORMAT_VALUE, "num of '-to_addr' and '-value' should be equal");
            return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_VALUE_OR_INVALID_FORMAT_VALUE;
        }

        l_value = DAP_NEW_Z_COUNT(uint256_t, l_value_el_count);
        if (!l_value) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_MEMORY_ERR, c_error_memory_alloc);
            return DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_MEMORY_ERR;
        }
        char **l_value_array = dap_strsplit(l_value_str, ",", l_value_el_count);
        if (!l_value_array) {
            DAP_DELETE(l_value);
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_PARAM_ERR, "Can't read '-to_addr' arg");
            return DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_PARAM_ERR;
        }
        for (size_t i = 0; i < l_value_el_count; ++i) {
            l_value[i] = dap_chain_balance_scan(l_value_array[i]);
            if(IS_ZERO_256(l_value[i])) {
                DAP_DEL_MULTY(l_value_array, l_value);
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_VALUE_OR_INVALID_FORMAT_VALUE, "tx_create requires parameter '-value' to be valid uint256 value");
                return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_VALUE_OR_INVALID_FORMAT_VALUE;
            }
        }
        dap_strfreev(l_value_array);
    
        l_addr_to = DAP_NEW_Z_COUNT(dap_chain_addr_t *, l_addr_el_count);
        if (!l_addr_to) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            DAP_DELETE(l_value);
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_MEMORY_ERR, c_error_memory_alloc);
            return DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_MEMORY_ERR;
        }
        char **l_addr_base58_to_array = dap_strsplit(addr_base58_to, ",", l_addr_el_count);
        if (!l_addr_base58_to_array) {
            DAP_DEL_MULTY(l_addr_to, l_value);
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_PARAM_ERR, "Can't read '-to_addr' arg");
            return DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_PARAM_ERR;
        }
        for (size_t i = 0; i < l_addr_el_count; ++i) {
            l_addr_to[i] = dap_chain_addr_from_str(l_addr_base58_to_array[i]);
            if(!l_addr_to[i]) {
                DAP_DEL_ARRAY(l_addr_to, i);
                DAP_DEL_MULTY(l_addr_to, l_addr_base58_to_array, l_value);
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_DESTINATION_ADDRESS_INVALID, "destination address is invalid");
                return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_DESTINATION_ADDRESS_INVALID;
            }
        }
        dap_strfreev(l_addr_base58_to_array);
    }

    int l_ret = DAP_CHAIN_NODE_CLI_COM_TX_CREATE_OK;
    if (l_emission_hash_str) {
        char *l_tx_hash_str = NULL;
        if (!l_priv_key) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_NO_PRIVATE_KEY_DEFINED, "No private key defined for creating the underlying "
                                                   "transaction no '-wallet_fee' or '-cert' parameter specified.");
            l_ret = DAP_CHAIN_NODE_CLI_COM_TX_CREATE_NO_PRIVATE_KEY_DEFINED;
        }
        l_tx_hash_str = dap_chain_mempool_base_tx_create(l_chain, &l_emission_hash, l_emission_chain->id,
                                                         uint256_0, NULL, NULL, // Get this params from emission itself
                                                         l_priv_key, l_hash_out_type, l_value_fee);
        json_object *l_jobj_emission = json_object_new_object();
        json_object *l_jobj_emi_status = NULL;
        json_object *l_jobj_emi_hash = NULL;
        if (l_tx_hash_str) {
            l_jobj_emi_status = json_object_new_string("Ok");
            l_jobj_emi_hash = json_object_new_string(l_tx_hash_str);
            DAP_DELETE(l_tx_hash_str);
            json_object_object_add(l_jobj_emission, "emission", l_jobj_emi_status);
            json_object_object_add(l_jobj_emission, "hash", l_jobj_emi_hash);
        } else {
            l_jobj_emi_status = json_object_new_string("False");
            json_object_object_add(l_jobj_emission, "emission", l_jobj_emi_status);
            json_object *l_jobj_msg = json_object_new_string("Can't place TX datum in mempool, examine log files\n");
            json_object_object_add(l_jobj_emission, "message", l_jobj_msg);
            l_ret = DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CAN_NOT_ADD_DATUM_IN_MEMPOOL;
        }
        json_object_array_add(*a_json_arr_reply, l_jobj_emission);
        DAP_DEL_ARRAY(l_addr_to, l_addr_el_count);
        DAP_DEL_MULTY(l_addr_to, l_value);
        if (l_wallet_fee) {
            dap_chain_wallet_close(l_wallet_fee);
            dap_enc_key_delete(l_priv_key);
        }
        return l_ret;        
    }

    dap_chain_wallet_t * l_wallet = dap_chain_wallet_open(l_from_wallet_name, c_wallets_path, NULL);
    json_object *l_jobj_result = json_object_new_object();

    if(!l_wallet) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_WALLET_DOES_NOT_EXIST,
                               "wallet %s does not exist", l_from_wallet_name);
        DAP_DEL_ARRAY(l_addr_to, l_addr_el_count);
        DAP_DEL_MULTY(l_addr_to, l_value);
        return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_WALLET_DOES_NOT_EXIST;
    } else {
        const char *l_wallet_check_str = dap_chain_wallet_check_sign(l_wallet);
        if (dap_strcmp(l_wallet_check_str, "") != 0) {
            json_object *l_obj_wgn_str = json_object_new_string(l_wallet_check_str);
            json_object_object_add(l_jobj_result, "warning", l_obj_wgn_str);
        }
    }
    dap_chain_addr_t *l_addr_from = dap_chain_wallet_get_addr(l_wallet, l_net->pub.id);

    if (!l_addr_from) {
        dap_chain_wallet_close(l_wallet);
        dap_enc_key_delete(l_priv_key);
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_SOURCE_ADDRESS_INVALID, "source address is invalid");
        json_object_put(l_jobj_result);
        DAP_DEL_ARRAY(l_addr_to, l_addr_el_count);
        DAP_DEL_MULTY(l_addr_to, l_value);
        return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_SOURCE_ADDRESS_INVALID;
    }

    for (size_t i = 0; i < l_addr_el_count; ++i) {
        if (dap_chain_addr_compare(l_addr_to[i], l_addr_from)) {
            dap_chain_wallet_close(l_wallet);
            dap_enc_key_delete(l_priv_key);
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_EQ_SOURCE_DESTINATION_ADDRESS, "The transaction cannot be directed to the same address as the source.");
            json_object_put(l_jobj_result);
            DAP_DEL_ARRAY(l_addr_to, l_addr_el_count);
            DAP_DEL_MULTY(l_addr_to, l_value);
            return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_EQ_SOURCE_DESTINATION_ADDRESS;
        }
    }

    for (size_t i = 0; i < l_addr_el_count; ++i) {
        if (l_addr_to[i]->net_id.uint64 != l_net->pub.id.uint64 && !dap_chain_addr_is_blank(l_addr_to[i])) {
            bool l_found = false;
            for (size_t j = 0; j < l_net->pub.bridged_networks_count; ++j) {
                if (l_net->pub.bridged_networks[j].uint64 == l_addr_to[i]->net_id.uint64) {
                    l_found = true;
                    break;
                }
            }
            if (!l_found) {
                dap_string_t *l_allowed_list = dap_string_new("");
                dap_string_append_printf(l_allowed_list, "0x%016"DAP_UINT64_FORMAT_X, l_net->pub.id.uint64);
                for (size_t j = 0; j < l_net->pub.bridged_networks_count; ++j)
                    dap_string_append_printf(l_allowed_list, ", 0x%016"DAP_UINT64_FORMAT_X, l_net->pub.bridged_networks[j].uint64);
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_DESTINATION_NETWORK_IS_UNREACHEBLE,
                                    "Destination network ID=0x%"DAP_UINT64_FORMAT_x
                                    " is unreachable. List of available network IDs:\n%s"
                                    " Please, change network name or wallet address",
                                    l_addr_to[i]->net_id.uint64, l_allowed_list->str);
                dap_string_free(l_allowed_list, true);
                json_object_put(l_jobj_result);

                DAP_DEL_ARRAY(l_addr_to, l_addr_el_count);
                DAP_DEL_MULTY(l_addr_to, l_value);
                return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_DESTINATION_NETWORK_IS_UNREACHEBLE;
            }
        }
    }

    dap_time_t l_time_lock = 0;
    if (l_time_str) {
        l_time_lock = dap_time_from_str_rfc822(l_time_str);
        if (!l_time_lock) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_WRONG_TIME_FORMAT,
                                    "Wrong time format. Parameter -lock_before must be in format \"Day Month Year HH:MM:SS Timezone\" e.g. \"19 August 2024 22:00:00 +00\"");
            return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_WRONG_TIME_FORMAT;
        }
    }

    json_object *l_jobj_transfer_status = NULL;
    json_object *l_jobj_tx_hash = NULL;

    l_priv_key = dap_chain_wallet_get_key(l_wallet, 0);
    if(l_tx_num){
        l_ret = dap_chain_mempool_tx_create_massive(l_chain, l_priv_key, l_addr_from,
                                                  l_addr_to[0], l_token_ticker, l_value[0], l_value_fee, l_tx_num);
        l_jobj_transfer_status = json_object_new_string((l_ret == 0) ? "Ok" : (l_ret == -2) ? "False, not enough funds for transfer" : "False");
        json_object_object_add(l_jobj_result, "transfer", l_jobj_transfer_status);
    } else {
        char *l_tx_hash_str = dap_chain_mempool_tx_create(l_chain, l_priv_key, l_addr_from, l_addr_to,
                                                          l_token_ticker, l_value, l_value_fee, l_hash_out_type,
                                                          l_addr_el_count, l_time_lock);
        if (l_tx_hash_str) {
            l_jobj_transfer_status = json_object_new_string("Ok");
            l_jobj_tx_hash = json_object_new_string(l_tx_hash_str);
            json_object_object_add(l_jobj_result, "transfer", l_jobj_transfer_status);
            json_object_object_add(l_jobj_result, "hash", l_jobj_tx_hash);
            DAP_DELETE(l_tx_hash_str);
        } else {
            l_jobj_transfer_status = json_object_new_string("False");
            json_object_object_add(l_jobj_result, "transfer", l_jobj_transfer_status);
            l_ret = DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CAN_NOT_CREATE_TRANSACTION;
        }
    }
    json_object_array_add(*a_json_arr_reply, l_jobj_result);

    DAP_DEL_ARRAY(l_addr_to, l_addr_el_count);
    DAP_DEL_MULTY(l_addr_from, l_addr_to, l_value);
    dap_chain_wallet_close(l_wallet);
    dap_enc_key_delete(l_priv_key);
    return l_ret;
}


/**
 * @brief Create transaction from json file
 * com_json_datum_mempool_put command
 * @param argc
 * @param argv
 * @param arg_func
 * @param str_reply
 * @return int
 */
int com_mempool_add(int a_argc, char ** a_argv, void **a_json_arr_reply, UNUSED_ARG int a_version)
{
    int l_arg_index = 1;
    const char *l_net_name = NULL; // optional parameter
    const char *l_chain_name = NULL; // optional parameter
    const char *l_json_file_path = NULL;
    const char *l_json_str = NULL;

    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_name); // optional parameter
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-chain", &l_chain_name); // optional parameter
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-json", &l_json_file_path);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-tx_obj", &l_json_str);

    if(!l_json_file_path && !l_json_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NET_TX_CREATE_JSON_REQUIRE_PARAMETER_JSON,
                               "Command requires one of parameters '-json <json file path> or -tx_obj <string>'");
        return DAP_CHAIN_NET_TX_CREATE_JSON_REQUIRE_PARAMETER_JSON;
    } 

    // Open json file
    struct json_object *l_json = NULL;
    if (l_json_file_path){
        l_json = json_object_from_file(l_json_file_path);
        if(!l_json) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NET_TX_CREATE_JSON_CAN_NOT_OPEN_JSON_FILE,
                                "Can't open json file: %s", json_util_get_last_err());
            return DAP_CHAIN_NET_TX_CREATE_JSON_CAN_NOT_OPEN_JSON_FILE;
        }
    } else if (l_json_str) {
        l_json = json_tokener_parse(l_json_str);
        if(!l_json) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NET_TX_CREATE_JSON_CAN_NOT_OPEN_JSON_FILE,
                                "Can't parse input JSON-string", json_util_get_last_err());
            return DAP_CHAIN_NET_TX_CREATE_JSON_CAN_NOT_OPEN_JSON_FILE;
        }
    }
    if(!json_object_is_type(l_json, json_type_object)) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NET_TX_CREATE_JSON_WRONG_JSON_FORMAT, "Wrong json format");
        json_object_put(l_json);
        return DAP_CHAIN_NET_TX_CREATE_JSON_WRONG_JSON_FORMAT;
    }

    
    // Read network from json file
    if(!l_net_name) {
        struct json_object *l_json_net = json_object_object_get(l_json, "net");
        if(l_json_net && json_object_is_type(l_json_net, json_type_string)) {
            l_net_name = json_object_get_string(l_json_net);
        }
        if(!l_net_name) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NET_TX_CREATE_JSON_REQUIRE_PARAMETER_NET,
                                   "Command requires parameter '-net' or set net in the json file");
            json_object_put(l_json);
            return DAP_CHAIN_NET_TX_CREATE_JSON_REQUIRE_PARAMETER_NET;
        }
    }
    dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_name);
    if(!l_net) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NET_TX_CREATE_JSON_NOT_FOUNT_NET_BY_NAME, "Not found net by name '%s'", l_net_name);
        json_object_put(l_json);
        return DAP_CHAIN_NET_TX_CREATE_JSON_NOT_FOUNT_NET_BY_NAME;
    }
    
    // Read chain from json file
    if(!l_chain_name) {
        struct json_object *l_json_chain = json_object_object_get(l_json, "chain");
        if(l_json_chain && json_object_is_type(l_json_chain, json_type_string)) {
            l_chain_name = json_object_get_string(l_json_chain);
        }
    }
    dap_chain_t *l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_name);
    if(!l_chain) {
        l_chain = dap_chain_net_get_chain_by_chain_type(l_net, CHAIN_TYPE_TX);
    }
    if(!l_chain) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NET_TX_CREATE_JSON_NOT_FOUNT_CHAIN_BY_NAME,
                               "Chain name '%s' not found, try use parameter '-chain' or set chain in the json file", l_chain_name);
        json_object_put(l_json);
        return DAP_CHAIN_NET_TX_CREATE_JSON_NOT_FOUNT_CHAIN_BY_NAME;
    }
    
    json_object *l_jobj_arr_errors = json_object_new_array();
    size_t l_items_ready = 0, l_items_count = 0;
    dap_chain_datum_tx_t *l_tx = NULL;
    int l_ret = 0;
    l_ret = dap_chain_tx_datum_from_json(l_json, l_net, l_jobj_arr_errors, &l_tx, &l_items_count, &l_items_ready);

    json_object *l_jobj_ret = json_object_new_object();

    if(l_items_ready < l_items_count || l_ret) {
        json_object *l_tx_create = json_object_new_boolean(false);
        json_object *l_jobj_valid_items = json_object_new_uint64(l_items_ready);
        json_object *l_jobj_total_items = json_object_new_uint64(l_items_count);
        json_object_object_add(l_jobj_ret, "tx_create", l_tx_create);
        json_object_object_add(l_jobj_ret, "valid_items", l_jobj_valid_items);
        json_object_object_add(l_jobj_ret, "total_items", l_jobj_total_items);
        json_object_object_add(l_jobj_ret, "errors", l_jobj_arr_errors);

        if (l_tx) DAP_DELETE(l_tx);
        if (l_ret)
            dap_json_rpc_error_add(*a_json_arr_reply, l_ret,
                                   "Can't create transaction from json file");
        json_object_array_add(*a_json_arr_reply, l_jobj_ret);
        return DAP_CHAIN_NET_TX_CREATE_JSON_INVALID_ITEMS;
    }
    json_object_put(l_jobj_arr_errors);

    // Pack transaction into the datum
    dap_chain_datum_t *l_datum_tx = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, dap_chain_datum_tx_get_size(l_tx));
    size_t l_datum_tx_size = dap_chain_datum_size(l_datum_tx);
    if (l_tx) DAP_DELETE(l_tx);

    // Add transaction to mempool
    char *l_gdb_group_mempool_base_tx = dap_chain_net_get_gdb_group_nochain_new(l_chain);// get group name for mempool
    char *l_tx_hash_str = dap_get_data_hash_str(l_datum_tx->data, l_datum_tx->header.data_size).s;
    bool l_placed = !dap_global_db_set(l_gdb_group_mempool_base_tx, l_tx_hash_str, l_datum_tx, l_datum_tx_size, false, NULL, NULL);

    DAP_DEL_Z(l_datum_tx);
    DAP_DELETE(l_gdb_group_mempool_base_tx);
    if(!l_placed) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NET_TX_CREATE_JSON_CAN_NOT_ADD_TRANSACTION_TO_MEMPOOL,
                               "Can't add transaction to mempool");
        return DAP_CHAIN_NET_TX_CREATE_JSON_CAN_NOT_ADD_TRANSACTION_TO_MEMPOOL;
    }
    // Completed successfully
    json_object *l_jobj_tx_create = json_object_new_boolean(true);
    json_object *l_jobj_hash = json_object_new_string(l_tx_hash_str);
    json_object *l_jobj_total_items = json_object_new_uint64(l_items_ready);
    json_object_object_add(l_jobj_ret, "tx_create", l_jobj_tx_create);
    json_object_object_add(l_jobj_ret, "hash", l_jobj_hash);
    json_object_object_add(l_jobj_ret, "total_items", l_jobj_total_items);
    json_object_array_add(*a_json_arr_reply, l_jobj_ret);
    return DAP_CHAIN_NET_TX_CREATE_JSON_OK;
}



/**
 * @brief com_tx_verify
 * Verifing transaction
 * tx_verify command
 * @param argc
 * @param argv
 * @param arg_func
 * @param str_reply
 * @return int
 */
int com_tx_verify(int a_argc, char **a_argv, void **a_str_reply, UNUSED_ARG int a_version)
{
    json_object **a_json_arr_reply = (json_object **)a_str_reply;
    const char * l_tx_hash_str = NULL;
    dap_chain_net_t * l_net = NULL;
    dap_chain_t * l_chain = NULL;
    int l_arg_index = 1;

    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-tx", &l_tx_hash_str);
    if(!l_tx_hash_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_VERIFY_REQUIRE_PARAMETER_TX, "tx_verify requires parameter '-tx'");
        return DAP_CHAIN_NODE_CLI_COM_TX_VERIFY_REQUIRE_PARAMETER_TX;
    }
    dap_chain_node_cli_cmd_values_parse_net_chain_for_json(*a_json_arr_reply, &l_arg_index, a_argc, a_argv, &l_chain, &l_net,
                                                           CHAIN_TYPE_TX);
    if (!l_net || !l_chain) {
        return DAP_CHAIN_NODE_CLI_COM_TX_VERIFY_NET_CHAIN_UNDEFINED;
    }
    dap_hash_fast_t l_tx_hash;
    char *l_hex_str_from58 = NULL;
    if (dap_chain_hash_fast_from_hex_str(l_tx_hash_str, &l_tx_hash)) {
        l_hex_str_from58 = dap_enc_base58_to_hex_str_from_str(l_tx_hash_str);
        if (dap_chain_hash_fast_from_hex_str(l_hex_str_from58, &l_tx_hash)) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_VERIFY_INVALID_TX_HASH, "Invalid tx hash format, need hex or base58");
            return DAP_CHAIN_NODE_CLI_COM_TX_VERIFY_INVALID_TX_HASH;
        }
    }
    size_t l_datum_size = 0;
    char *l_gdb_group = dap_chain_mempool_group_new(l_chain);
    dap_chain_datum_t *l_datum = (dap_chain_datum_t*)dap_global_db_get_sync(l_gdb_group, l_hex_str_from58 ? l_hex_str_from58 : l_tx_hash_str, &l_datum_size, NULL, NULL);
    DAP_DEL_Z(l_hex_str_from58);
    if (!l_datum) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_VERIFY_SPECIFIED_TX_NOT_FOUND, "Specified tx not found");
        return DAP_CHAIN_NODE_CLI_COM_TX_VERIFY_SPECIFIED_TX_NOT_FOUND;
    }
    if (l_datum->header.type_id != DAP_CHAIN_DATUM_TX){
        char *l_str_err = dap_strdup_printf("Based on the specified hash, the type %s was found and not a transaction.",
                                            dap_chain_datum_type_id_to_str(l_datum->header.type_id));
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_VERIFY_HASH_IS_NOT_TX_HASH, l_str_err);
        DAP_DELETE(l_str_err);
        return DAP_CHAIN_NODE_CLI_COM_TX_VERIFY_HASH_IS_NOT_TX_HASH;
    }
    dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t*)l_datum->data;
    int l_ret = dap_ledger_tx_add_check(l_net->pub.ledger, l_tx, l_datum->header.data_size, &l_tx_hash);
    json_object *l_obj_ret = json_object_new_object();
    json_object *l_obj_hash = json_object_new_string(l_tx_hash_str);
    json_object_object_add(l_obj_ret, "hash", l_obj_hash);
    json_object *l_jobj_verfiy = NULL;
    json_object *l_jobj_error = NULL;
    if (l_ret) {
        l_jobj_verfiy = json_object_new_boolean(false);
        l_jobj_error = json_object_new_object();
        json_object *l_jobj_err_str = json_object_new_string(dap_ledger_check_error_str(l_ret));
        json_object *l_jobj_err_code = json_object_new_int64(l_ret);
        json_object_object_add(l_jobj_error, "code", l_jobj_err_code);
        json_object_object_add(l_jobj_error, "message", l_jobj_err_str);
        json_object_object_add(l_obj_ret, "verify", l_jobj_verfiy);
        json_object_object_add(l_obj_ret, "error", l_jobj_error);
        json_object_array_add(*a_json_arr_reply, l_obj_ret);
        return DAP_CHAIN_NODE_CLI_COM_TX_VERIFY_TX_NOT_VERIFY;
    } else {
        l_jobj_verfiy = json_object_new_boolean(true);
        l_jobj_error = json_object_new_null();
        json_object_object_add(l_obj_ret, "verify", l_jobj_verfiy);
        json_object_object_add(l_obj_ret, "error", l_jobj_error);
        json_object_array_add(*a_json_arr_reply, l_obj_ret);
        return DAP_CHAIN_NODE_CLI_COM_TX_VERIFY_OK;
    }
}


/**
 * @brief com_tx_history
 * tx_history command
 * Transaction history for an address
 * @param a_argc
 * @param a_argv
 * @param a_str_reply
 * @return int
 */
int com_tx_history(int a_argc, char ** a_argv, void **a_str_reply, int a_version)
{
    json_object **a_json_arr_reply = (json_object **)a_str_reply;
    int arg_index = 1;
    const char *l_addr_base58 = NULL;
    const char *l_wallet_name = NULL;
    const char *l_net_str = NULL;
    const char *l_chain_str = NULL;
    const char *l_tx_hash_str = NULL;
    const char *l_tx_srv_str = NULL;
    const char *l_tx_act_str = NULL;
    const char *l_limit_str = NULL;
    const char *l_offset_str = NULL;
    const char *l_head_str = NULL;

    dap_chain_t * l_chain = NULL;
    dap_chain_net_t * l_net = NULL;

    const char * l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_PARAM_ERR,
                                "Invalid parameter -H, valid values: -H <hex | base58>");
        return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_PARAM_ERR;

    }

    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-addr", &l_addr_base58);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-w", &l_wallet_name);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_str);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-chain", &l_chain_str);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-tx", &l_tx_hash_str);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-srv", &l_tx_srv_str);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-act", &l_tx_act_str);

    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-limit", &l_limit_str);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-offset", &l_offset_str);
    bool l_head = dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-head", &l_head_str) ? true : false;
    size_t l_limit = l_limit_str ? strtoul(l_limit_str, NULL, 10) : 1000;
    size_t l_offset = l_offset_str ? strtoul(l_offset_str, NULL, 10) : 0;

    //default is ALL/ANY
    dap_chain_tx_tag_action_type_t l_action = l_tx_act_str ? dap_ledger_tx_action_str_to_action_t(l_tx_act_str):
                                     DAP_CHAIN_TX_TAG_ACTION_ALL;

    bool l_brief = (dap_cli_server_cmd_check_option(a_argv, arg_index, a_argc, "-brief") != -1) ? true : false;

    bool l_is_tx_all = dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-all", NULL);
    bool l_is_tx_count = dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-count", NULL);

    if (!l_addr_base58 && !l_wallet_name && !l_tx_hash_str && !l_is_tx_all && !l_is_tx_count) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_PARAM_ERR,
                                "tx_history requires parameter '-addr' or '-w' or '-tx'");
        return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_PARAM_ERR;
    }

    if (!l_net_str && !l_addr_base58&& !l_is_tx_all) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_PARAM_ERR,
                                "tx_history requires parameter '-net' or '-addr'");
        return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_PARAM_ERR;
    }

    dap_chain_hash_fast_t l_tx_hash;
    if (l_tx_hash_str && dap_chain_hash_fast_from_str(l_tx_hash_str, &l_tx_hash) != 0) {

        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_HASH_REC_ERR, "tx hash not recognized");
        return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_HASH_REC_ERR;
    }

    // Select chain network
    if (!l_addr_base58 && l_net_str) {
        l_net = dap_chain_net_by_name(l_net_str);
        if (!l_net) { // Can't find such network
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_NET_PARAM_ERR,
                                    "tx_history requires parameter '-net' to be valid chain network name");
            return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_NET_PARAM_ERR;
        }
    }
    // Get chain address
    dap_chain_addr_t *l_addr = NULL;
    if (l_addr_base58) {
        if (l_tx_hash_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_INCOMPATIBLE_PARAMS_ERR,
                                                        "Incompatible params '-addr' & '-tx'");
            return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_INCOMPATIBLE_PARAMS_ERR;
        }
        l_addr = dap_chain_addr_from_str(l_addr_base58);
        if (!l_addr) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_WALLET_ADDR_ERR,
                                                        "Wallet address not recognized");
            return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_WALLET_ADDR_ERR;
        }
        if (l_net) {
            if (l_net->pub.id.uint64 != l_addr->net_id.uint64) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_ID_NET_ADDR_DIF_ERR,
                                        "Network ID with '-net' param and network ID with '-addr' param are different");
                DAP_DELETE(l_addr);
                return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_ID_NET_ADDR_DIF_ERR;
            }
        } else
            l_net = dap_chain_net_by_id(l_addr->net_id);
    }
    if (l_wallet_name) {
        const char *c_wallets_path = dap_chain_wallet_get_path(g_config);
        dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_name, c_wallets_path, NULL);
        if (l_wallet) {
            const char *l_sign_str = dap_chain_wallet_check_sign(l_wallet);
            //TODO add warning about deprecated signs
            dap_chain_addr_t *l_addr_tmp = dap_chain_wallet_get_addr(l_wallet, l_net->pub.id);
            if (l_addr) {
                if (!dap_chain_addr_compare(l_addr, l_addr_tmp)) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_ADDR_WALLET_DIF_ERR,
                                            "Address with '-addr' param and address with '-w' param are different");
                    DAP_DELETE(l_addr);
                    DAP_DELETE(l_addr_tmp);
                    return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_ADDR_WALLET_DIF_ERR;
                }
                DAP_DELETE(l_addr_tmp);
            } else
                l_addr = l_addr_tmp;
            dap_chain_wallet_close(l_wallet);
        } else {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_WALLET_ERR,
                                    "The wallet %s is not activated or it doesn't exist", l_wallet_name);
            DAP_DELETE(l_addr);
            return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_WALLET_ERR;
        }
    }
    // Select chain, if any
    if (!l_net) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_NET_ERR, "Could not determine the network from which to "
                                                       "extract data for the tx_history command to work.");
        return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_NET_ERR;
    }
    if (l_chain_str)
        l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_str);
    else
        l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_TX);

    if(!l_chain) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_CHAIN_PARAM_ERR,
                                "tx_history requires parameter '-chain' to be valid chain name in chain net %s."
                                " You can set default datum type in chain configuration file", l_net_str);
        return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_CHAIN_PARAM_ERR;
    }
    // response
    json_object * json_obj_out = NULL;
    if (l_tx_hash_str) {
         // history tx hash
        json_obj_out = dap_db_history_tx(*a_json_arr_reply, &l_tx_hash, l_chain, l_hash_out_type, l_net, a_version);
        if (!json_obj_out) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_DAP_DB_HISTORY_TX_ERR,
                                    "something went wrong in tx_history");
            return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_DAP_DB_HISTORY_TX_ERR;
        }
    } else if (l_addr) {
        // history addr and wallet
        json_object * json_obj_summary = json_object_new_object();
        if (!json_obj_summary) {
            return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_MEMORY_ERR;
        }
        json_obj_out = dap_db_history_addr(*a_json_arr_reply, l_addr, l_chain, l_hash_out_type, dap_chain_addr_to_str_static(l_addr), json_obj_summary, l_limit, l_offset, l_brief, l_tx_srv_str, l_action, l_head, a_version);
        if (!json_obj_out) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_DAP_DB_HISTORY_ADDR_ERR,
                                    "something went wrong in tx_history");
            json_object_put(json_obj_summary);
            return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_DAP_DB_HISTORY_ADDR_ERR;
        }
        json_object_array_add(*a_json_arr_reply, json_obj_out);
        json_object_array_add(*a_json_arr_reply, json_obj_summary);
        return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_OK;
    } else if (l_is_tx_all) {
        // history all
        json_object * json_obj_summary = json_object_new_object();
        if (!json_obj_summary) {
            return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_MEMORY_ERR;
        }

        json_object* json_arr_history_all = dap_db_history_tx_all(*a_json_arr_reply, l_chain, l_net, l_hash_out_type, json_obj_summary,
                                                                l_limit, l_offset, l_brief, l_tx_srv_str, l_action, l_head, a_version);
        if (!json_arr_history_all) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_DAP_DB_HISTORY_ALL_ERR,
                                    "something went wrong in tx_history");
            return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_DAP_DB_HISTORY_ALL_ERR;
        }

        json_object_array_add(*a_json_arr_reply, json_arr_history_all);
        json_object_array_add(*a_json_arr_reply, json_obj_summary);
        return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_OK;
    } else if (l_is_tx_count) {
        json_object * json_count_obj= json_object_new_object();
        json_object_object_add(json_count_obj, "number_of_transaction", json_object_new_uint64(l_chain->callback_count_tx(l_chain)));
        json_object_array_add(*a_json_arr_reply, json_count_obj);
        return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_OK;
    }

    if (json_obj_out) {
        const char* json_string_sdfasf = json_object_to_json_string(*a_json_arr_reply);
        char* result_string_sadfasf = strdup(json_string_sdfasf);
        json_object_array_add(*a_json_arr_reply, json_obj_out);
        const char* json_string = json_object_to_json_string(*a_json_arr_reply);
        char* result_string = strdup(json_string);
    } else {
        json_object_array_add(*a_json_arr_reply, json_object_new_string("empty"));
    }

    return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_OK;
}

/**
 * @brief com_tx_cond_create
 * Create transaction
 * com_tx_cond_create command
 * @param a_argc
 * @param a_argv
 * @param a_str_reply
 * @return int
 */
int com_tx_cond_create(int a_argc, char ** a_argv, void **a_str_reply, UNUSED_ARG int a_version)
{
    (void) a_argc;
    json_object** a_json_arr_reply = (json_object**)a_str_reply;
    int arg_index = 1;
    const char *c_wallets_path = dap_chain_wallet_get_path(g_config);
    const char * l_token_ticker = NULL;
    const char * l_wallet_str = NULL;
    const char * l_cert_str = NULL;
    const char * l_value_str = NULL;
    const char * l_value_fee_str = NULL;
    const char * l_net_name = NULL;
    const char * l_unit_str = NULL;
    const char * l_srv_uid_str = NULL;
    uint256_t l_value_datoshi = {};
    uint256_t l_value_fee = {};
    const char * l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_INVALID_PARAMETER_HEX,
                               "Invalid parameter -H, valid values: -H <hex | base58>");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_INVALID_PARAMETER_HEX;
    }

    // Token ticker
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-token", &l_token_ticker);
    // Wallet name - from
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-w", &l_wallet_str);
    // Public certifiacte of condition owner
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-cert", &l_cert_str);
    // value datoshi
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-value", &l_value_str);
    // fee
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-fee", &l_value_fee_str);
    // net
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_name);
    // unit
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-unit", &l_unit_str);
    // service
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-srv_uid", &l_srv_uid_str);

    if(!l_token_ticker) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_TOKEN, "tx_cond_create requires parameter '-token'");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_TOKEN;
    }
    if (!l_wallet_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_W, "tx_cond_create requires parameter '-w'");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_W;
    }
    if (!l_cert_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_CERT, "tx_cond_create requires parameter '-cert'");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_CERT;
    }
    if (!l_value_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_VALUE, "tx_cond_create requires parameter '-value'");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_VALUE;
    }
    if(!l_value_fee_str){
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_FEE, "tx_cond_create requires parameter '-fee'");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_FEE;
    }
    if(!l_net_name) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_NET, "tx_cond_create requires parameter '-net'");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_NET;
    }
    if(!l_unit_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_UNIT, "tx_cond_create requires parameter '-unit'");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_UNIT;
    }

    if(!l_srv_uid_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_SRV_UID, "tx_cond_create requires parameter '-srv_uid'");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_SRV_UID;
    }
    dap_chain_srv_uid_t l_srv_uid = {};
    l_srv_uid.uint64 = strtoll(l_srv_uid_str, NULL, 10);
    if (!l_srv_uid.uint64) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_NOT_FIND_SERVICE_UID, "Can't find service UID %s ", l_srv_uid_str);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_NOT_FIND_SERVICE_UID;
    }

    dap_chain_net_srv_price_unit_uid_t l_price_unit = { .enm = dap_chain_srv_str_to_unit_enum((char*)l_unit_str)};

    if(l_price_unit.enm == SERV_UNIT_UNDEFINED) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_NOT_RECOGNIZE_UNIT,
                               "Can't recognize unit '%s'. Unit must look like { B | SEC }", l_unit_str);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_NOT_RECOGNIZE_UNIT;
    }

    l_value_datoshi = dap_chain_balance_scan(l_value_str);
    if (IS_ZERO_256(l_value_datoshi)) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_NOT_RECOGNIZE_VALUE,
                               "Can't recognize value '%s' as a number", l_value_str);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_NOT_RECOGNIZE_VALUE;
    }

    l_value_fee = dap_chain_balance_scan(l_value_fee_str);
    if(IS_ZERO_256(l_value_fee)) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_NOT_RECOGNIZE_VALUE_FEE,
                               "Can't recognize value '%s' as a number", l_value_fee_str);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_NOT_RECOGNIZE_VALUE_FEE;
    }

    dap_chain_net_t * l_net = l_net_name ? dap_chain_net_by_name(l_net_name) : NULL;
    if(!l_net) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_NOT_FIND_NET, "Can't find net '%s'", l_net_name);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_NOT_FIND_NET;
    }
    dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, c_wallets_path, NULL);
//    const char* l_sign_str = "";
    if(!l_wallet) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_NOT_OPEN_WALLET, "Can't open wallet '%s'", l_wallet_str);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_NOT_OPEN_WALLET;
    } else {
//        l_sign_str = dap_chain_wallet_check_sign(l_wallet);
    }

    dap_cert_t *l_cert_cond = dap_cert_find_by_name(l_cert_str);
    if(!l_cert_cond) {
        dap_chain_wallet_close(l_wallet);
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_FIND_CERT, "Can't find cert '%s'", l_cert_str);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_FIND_CERT;
    }

    dap_enc_key_t *l_key_from = dap_chain_wallet_get_key(l_wallet, 0);
    dap_pkey_t *l_key_cond = dap_pkey_from_enc_key(l_cert_cond->enc_key);
    if (!l_key_cond) {
        dap_chain_wallet_close(l_wallet);
        dap_enc_key_delete(l_key_from);
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CERT_DOES_NOT_CONATIN_VALID_PUBLIC_KEY,
                               "Cert '%s' doesn't contain a valid public key", l_cert_str);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CERT_DOES_NOT_CONATIN_VALID_PUBLIC_KEY;
    }

    uint256_t l_value_per_unit_max = {};
    char *l_hash_str = dap_chain_mempool_tx_create_cond(l_net, l_key_from, l_key_cond, l_token_ticker,
                                                        l_value_datoshi, l_value_per_unit_max, l_price_unit,
                                                        l_srv_uid, l_value_fee, NULL, 0, l_hash_out_type);
    dap_chain_wallet_close(l_wallet);
    dap_enc_key_delete(l_key_from);
    DAP_DELETE(l_key_cond);

    if (l_hash_str) {
        json_object *l_jobj_ret = json_object_new_object();
        json_object *l_jobj_tx_cond_transfer = json_object_new_boolean(true);
        json_object *l_jobj_hash = json_object_new_string(l_hash_str);
        json_object_object_add(l_jobj_ret, "create_tx_cond", l_jobj_tx_cond_transfer);
        json_object_object_add(l_jobj_ret, "hash", l_jobj_hash);
        json_object_array_add(*a_json_arr_reply, l_jobj_ret);
        DAP_DELETE(l_hash_str);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_OK;
    }
    json_object *l_jobj_ret = json_object_new_object();
    json_object *l_jobj_tx_cond_transfer = json_object_new_boolean(false);
    json_object_object_add(l_jobj_ret, "create_tx_cond", l_jobj_tx_cond_transfer);
    json_object_array_add(*a_json_arr_reply, l_jobj_ret);
    return DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_NOT_CONDITIONAL_TX_CREATE;
}

static dap_list_t* s_hashes_parse_str_list(const char *a_hashes_str)
{
    dap_list_t *l_ret_list = NULL;
    char *l_hash_str_dup = strdup(a_hashes_str), *l_hash_str, *l_hashes_tmp_ptrs = NULL;
    if (!l_hash_str_dup)
        return log_it(L_CRITICAL, "%s", c_error_memory_alloc), NULL;
    dap_hash_fast_t l_hash = { };
    while (( l_hash_str = strtok_r(l_hash_str_dup, ",", &l_hashes_tmp_ptrs) )) {
        l_hash_str = dap_strstrip(l_hash_str);
        if (dap_chain_hash_fast_from_str(l_hash_str, &l_hash)){
            log_it(L_ERROR, "Can't get hash of string \"%s\". Continue.", l_hash_str);
            continue;
        }
        l_ret_list = dap_list_append(l_ret_list, DAP_DUP(&l_hash));
    }
    DAP_DELETE(l_hash_str_dup);
    return l_ret_list;
}

int com_tx_cond_remove(int a_argc, char ** a_argv, void **a_json_arr_reply, UNUSED_ARG int a_version)
{
    (void) a_argc;
    int arg_index = 1;
    const char *c_wallets_path = dap_chain_wallet_get_path(g_config);
    const char * l_wallet_str = NULL;
    const char * l_value_fee_str = NULL;
    const char * l_net_name = NULL;
    const char * l_hashes_str = NULL;
    const char * l_srv_uid_str = NULL;
    uint256_t l_value_datoshi = {};
    uint256_t l_value_fee = {};
    const char * l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_INVALID_PARAMETER_HEX,
                               "Invalid parameter -H, valid values: -H <hex | base58>");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_INVALID_PARAMETER_HEX;
    }

    // Wallet name
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-w", &l_wallet_str);
    // fee
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-fee", &l_value_fee_str);
    // net
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_name);
    // tx cond hahses
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-hashes", &l_hashes_str);
    // srv_uid
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-srv_uid", &l_srv_uid_str);

    if (!l_wallet_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_REQUIRES_PARAMETER_W, "com_txs_cond_remove requires parameter '-w'");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_REQUIRES_PARAMETER_W;
    }
    if(!l_value_fee_str){
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_REQUIRES_PARAMETER_FEE, "com_txs_cond_remove requires parameter '-fee'");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_REQUIRES_PARAMETER_FEE;
    }
    if(!l_net_name) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_REQUIRES_PARAMETER_NET, "com_txs_cond_remove requires parameter '-net'");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_REQUIRES_PARAMETER_NET;
    }
    if(!l_hashes_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_REQUIRES_PARAMETER_HASHES, "com_txs_cond_remove requires parameter '-hashes'");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_REQUIRES_PARAMETER_HASHES;
    }
    if(!l_srv_uid_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_REQUIRES_PARAMETER_SRV_UID, "com_txs_cond_remove requires parameter '-srv_uid'");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_REQUIRES_PARAMETER_SRV_UID;
    }

    dap_chain_srv_uid_t l_srv_uid = {};
    l_srv_uid.uint64 = strtoll(l_srv_uid_str, NULL, 10);
    if (!l_srv_uid.uint64) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_FIND_SERVICE_UID, "Can't find service UID %s ", l_srv_uid_str);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_FIND_SERVICE_UID;
    }

    dap_chain_net_t * l_net = l_net_name ? dap_chain_net_by_name(l_net_name) : NULL;
    if(!l_net) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_FIND_NET, "Can't find net '%s'", l_net_name);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_FIND_NET;
    }
    dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, c_wallets_path, NULL);
//    const char* l_sign_str = "";
    if(!l_wallet) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_OPEN_WALLET, "Can't open wallet '%s'", l_wallet_str);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_OPEN_WALLET;
    }

    dap_enc_key_t *l_key_from = dap_chain_wallet_get_key(l_wallet, 0);
    dap_pkey_t *l_wallet_pkey = dap_pkey_from_enc_key(l_key_from);

    l_value_fee = dap_chain_balance_scan(l_value_fee_str);
    if(IS_ZERO_256(l_value_fee)) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_RECOGNIZE_VALUE_FEE, "Can't recognize value '%s' as a number", l_value_fee_str);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_RECOGNIZE_VALUE_FEE;
    }

    const char *l_native_ticker = l_net->pub.native_ticker;
    if (!l_native_ticker){
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_FIND_NATIVE_TICKER_IN_NET, "Can't find native ticker for net %s", l_net->pub.name);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_FIND_NATIVE_TICKER_IN_NET;
    }
    dap_ledger_t *l_ledger = dap_ledger_by_net_name(l_net->pub.name);
    if (!l_ledger){
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_FIND_LEDGER_FOR_NET, "Can't find ledger for net %s", l_net->pub.name);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_FIND_LEDGER_FOR_NET;
    }
    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_ledger){
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_CREATE_NEW_TX, "Can't create new tx");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_CREATE_NEW_TX;
    }

    dap_list_t *l_hashes_list = s_hashes_parse_str_list(l_hashes_str);
    if (!l_hashes_list){
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_REQUESTED_COND_TX_WITH_HASH_NOT_FOUND, "Requested conditional transaction with hash not found");
        dap_chain_datum_tx_delete(l_tx);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_REQUESTED_COND_TX_WITH_HASH_NOT_FOUND;
    }

    uint256_t l_cond_value_sum = {};
    size_t l_num_of_hashes = dap_list_length(l_hashes_list);
    log_it(L_INFO, "Found %zu hashes. Start returning funds from transactions.", l_num_of_hashes);
    for (dap_list_t * l_tmp = l_hashes_list; l_tmp; l_tmp=l_tmp->next){
        dap_hash_fast_t *l_hash = (dap_hash_fast_t*)l_tmp->data;
        // get tx by hash
        dap_chain_datum_tx_t *l_cond_tx = dap_ledger_tx_find_by_hash(l_ledger, l_hash);
        if (!l_cond_tx) {
            char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
            dap_chain_hash_fast_to_str(l_hash, l_hash_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
            log_it(L_WARNING, "Requested conditional transaction with hash %s not found. Continue.", l_hash_str);
            continue;
        }

        const char *l_tx_ticker = dap_ledger_tx_get_token_ticker_by_hash(l_ledger, l_hash);
        if (!l_tx_ticker) {
            log_it(L_WARNING, "Can't get tx ticker");
            continue;
        }
        if (strcmp(l_native_ticker, l_tx_ticker)) {
            log_it(L_WARNING, "Tx must be in native ticker");
            continue;
        }

        // Get out_cond from l_cond_tx
        int l_prev_cond_idx = 0;
        dap_chain_tx_out_cond_t *l_tx_out_cond = dap_chain_datum_tx_out_cond_get(l_cond_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY,
                                                                             &l_prev_cond_idx);
        if (!l_tx_out_cond) {
            log_it(L_WARNING, "Requested conditional transaction has no contitional output with srv_uid %"DAP_UINT64_FORMAT_U, l_srv_uid.uint64);
            continue;
        }
        if (l_tx_out_cond->header.srv_uid.uint64 != l_srv_uid.uint64)
            continue;

        if (dap_ledger_tx_hash_is_used_out_item(l_ledger, l_hash, l_prev_cond_idx, NULL)) {
            log_it(L_WARNING, "Requested conditional transaction is already used out");
            continue;
        }
        // Get owner tx
        dap_hash_fast_t l_owner_tx_hash = dap_ledger_get_first_chain_tx_hash(l_ledger, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY, l_hash);
        dap_chain_datum_tx_t *l_owner_tx = dap_hash_fast_is_blank(&l_owner_tx_hash)
            ? l_cond_tx:
            dap_ledger_tx_find_by_hash(l_ledger, &l_owner_tx_hash);
        if (!l_owner_tx)
            continue;
        dap_chain_tx_sig_t *l_owner_tx_sig = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(l_owner_tx, NULL, NULL, TX_ITEM_TYPE_SIG, NULL);
        dap_sign_t *l_owner_sign = dap_chain_datum_tx_item_sig_get_sign((dap_chain_tx_sig_t *)l_owner_tx_sig);

        if (!l_owner_sign) {
            log_it(L_WARNING, "Can't get sign.");
            continue;
        }

        if (!dap_pkey_compare_with_sign(l_wallet_pkey, l_owner_sign)) {
            log_it(L_WARNING, "Only owner can return funds from tx cond");
            continue;
        }

        // get final tx
        dap_hash_fast_t l_final_hash = dap_ledger_get_final_chain_tx_hash(l_ledger, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY, l_hash, true);
        dap_chain_datum_tx_t *l_final_tx = dap_ledger_tx_find_by_hash(l_ledger, &l_final_hash);
        if (!l_final_tx) {
            log_it(L_WARNING, "Only get final tx hash or tx is already used out.");
            continue;
        }

        // get and check tx_cond_out
        int l_final_cond_idx = 0;
        dap_chain_tx_out_cond_t *l_final_tx_out_cond = dap_chain_datum_tx_out_cond_get(l_final_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY,
                                                                             &l_final_cond_idx);
        if (!l_final_tx_out_cond || IS_ZERO_256(l_final_tx_out_cond->header.value))
            continue;


        // add in_cond to new tx
        // add 'in' item to buy from conditional transaction
        dap_chain_datum_tx_add_in_cond_item(&l_tx, &l_final_hash, l_final_cond_idx, 0);
        SUM_256_256(l_cond_value_sum, l_final_tx_out_cond->header.value, &l_cond_value_sum);
    }
    dap_list_free_full(l_hashes_list, NULL);

    if (IS_ZERO_256(l_cond_value_sum)){
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_UNSPENT_COND_TX_IN_HASH_LIST_FOR_WALLET,
                               "No unspent conditional transactions in hashes list for wallet %s. Check input parameters.", l_wallet_str);
        dap_chain_datum_tx_delete(l_tx);
        dap_chain_wallet_close(l_wallet);
        DAP_DEL_Z(l_wallet_pkey);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_UNSPENT_COND_TX_IN_HASH_LIST_FOR_WALLET;
    }

    uint256_t l_net_fee = {};
    dap_chain_addr_t l_addr_fee = {};
    bool l_net_fee_used = dap_chain_net_tx_get_fee(l_net->pub.id, &l_net_fee, &l_addr_fee);
    uint256_t l_total_fee = l_value_fee;
    if (l_net_fee_used)
        SUM_256_256(l_total_fee, l_net_fee, &l_total_fee);

    if (compare256(l_total_fee, l_cond_value_sum) >= 0 ){
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_SUM_COND_OUTPUTS_MUST_GREATER_THAN_FEES_SUM,
                               "Sum of conditional outputs must be greater than fees sum.");
        dap_chain_datum_tx_delete(l_tx);
        dap_chain_wallet_close(l_wallet);
        DAP_DEL_Z(l_wallet_pkey);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_SUM_COND_OUTPUTS_MUST_GREATER_THAN_FEES_SUM;
    }

    uint256_t l_coin_back = {};
    SUBTRACT_256_256(l_cond_value_sum, l_total_fee, &l_coin_back);
    dap_chain_addr_t *l_wallet_addr = dap_chain_wallet_get_addr(l_wallet, l_net->pub.id);
    // return coins to owner
    if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_wallet_addr, l_coin_back, l_native_ticker) == -1) {
        dap_chain_datum_tx_delete(l_tx);
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_ADD_RETURNING_COINS_OUTPUT,
                               "Can't create new TX. Something went wrong.\n");
        log_it(L_ERROR, "Can't add returning coins output");
        DAP_DELETE(l_wallet_addr);
        dap_chain_wallet_close(l_wallet);
        DAP_DEL_Z(l_wallet_pkey);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_ADD_RETURNING_COINS_OUTPUT-22;
    }
     DAP_DELETE(l_wallet_addr);
    // Network fee
    if (l_net_fee_used &&
            dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr_fee, l_net_fee, l_native_ticker) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        dap_chain_wallet_close(l_wallet);
        DAP_DEL_Z(l_wallet_pkey);
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_ADD_NETWORK_FEE_OUTPUT, "Can't create new TX. Something went wrong.\n");
        log_it(L_ERROR, "Cant add network fee output");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_ADD_NETWORK_FEE_OUTPUT;
    }
    // Validator's fee
    if (dap_chain_datum_tx_add_fee_item(&l_tx, l_value_fee) == -1) {
        dap_chain_datum_tx_delete(l_tx);
        dap_chain_wallet_close(l_wallet);
        DAP_DEL_Z(l_wallet_pkey);
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_ADD_VALIDATORS_FEE_OUTPUT, "Can't create new TX. Something went wrong.\n");
        log_it(L_ERROR, "Cant add validator's fee output");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_ADD_VALIDATORS_FEE_OUTPUT;
    }

    // add 'sign' items
    dap_enc_key_t *l_owner_key = dap_chain_wallet_get_key(l_wallet, 0);
    if(dap_chain_datum_tx_add_sign_item(&l_tx, l_owner_key) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        dap_enc_key_delete(l_owner_key);
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_ADD_SIGN_OUTPUT, "Can't create new TX. Something went wrong.\n");
        log_it( L_ERROR, "Can't add sign output");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_ADD_SIGN_OUTPUT;
    }

    dap_chain_wallet_close(l_wallet);
    DAP_DEL_Z(l_wallet_pkey);

    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, l_tx_size);
    dap_chain_datum_tx_delete(l_tx);
    dap_chain_t *l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_TX);
    if (!l_chain) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_FIND_DEFAULT_CHAIN_WITH_TX_FOR_NET,
                               "Can't create new TX. Something went wrong.\n");
        DAP_DELETE(l_datum);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_FIND_DEFAULT_CHAIN_WITH_TX_FOR_NET;
    }
    // Processing will be made according to autoprocess policy
    char *l_hash_str = dap_chain_mempool_datum_add(l_datum, l_chain, "hex");
    DAP_DELETE(l_datum);

    if (l_hash_str) {
        json_object *l_jobj_ret = json_object_new_object();
        json_object *l_jobj_tx_status = json_object_new_boolean(true);
        json_object *l_jobj_tx_hash = json_object_new_string(l_hash_str);
        json_object_object_add(l_jobj_ret, "tx_create", l_jobj_tx_status);
        json_object_object_add(l_jobj_ret, "hash", l_jobj_tx_hash);
        DAP_DELETE(l_hash_str);
        json_object_array_add(*a_json_arr_reply, l_jobj_ret);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_OK;
    }
    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_OTHER_ERROR, "Can't create new TX. Something went wrong.");
    return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_OTHER_ERROR;
}

typedef struct tx_check_args {
    dap_chain_datum_tx_t *tx;
    dap_hash_fast_t tx_hash;
} tx_check_args_t;

void s_tx_is_srv_pay_check (dap_chain_net_t* a_net, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash, void *a_arg)
{
    UNUSED(a_net);
    dap_list_t **l_tx_list_ptr = a_arg;
    if (dap_chain_datum_tx_out_cond_get(a_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY , NULL)){
        tx_check_args_t *l_arg = DAP_NEW_Z(tx_check_args_t);
        l_arg->tx = a_tx;
        l_arg->tx_hash = *a_tx_hash;
        *l_tx_list_ptr = dap_list_append(*l_tx_list_ptr, l_arg);
    }

}

int com_tx_cond_unspent_find(int a_argc, char **a_argv, void **a_json_arr_reply, UNUSED_ARG int a_version)
{
    (void) a_argc;
    int arg_index = 1;
    const char *c_wallets_path = dap_chain_wallet_get_path(g_config);
    const char * l_wallet_str = NULL;
    const char * l_net_name = NULL;
    const char * l_srv_uid_str = NULL;

    const char * l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_INVALID_PARAMETER_HEX,
                               "Invalid parameter -H, valid values: -H <hex | base58>");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_INVALID_PARAMETER_HEX;
    }

    // Public certifiacte of condition owner
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-w", &l_wallet_str);
    // net
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_name);
    // srv_uid
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-srv_uid", &l_srv_uid_str);

    if (!l_wallet_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_INVALID_PARAMETER_W,
                               "com_txs_cond_remove requires parameter '-w'");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_INVALID_PARAMETER_W;
    }
    if(!l_net_name) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_INVALID_PARAMETER_NET,
                               "com_txs_cond_remove requires parameter '-net'");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_INVALID_PARAMETER_NET;
    }
    if(!l_srv_uid_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_INVALID_PARAMETER_SRV_UID,
                               "com_txs_cond_remove requires parameter '-srv_uid'");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_INVALID_PARAMETER_SRV_UID;
    }

    dap_chain_srv_uid_t l_srv_uid = {};
    l_srv_uid.uint64 = strtoll(l_srv_uid_str, NULL, 10);
    if (!l_srv_uid.uint64) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_CAN_NOT_FIND_SERVICE_UID,
                               "Can't find service UID %s ", l_srv_uid_str);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_CAN_NOT_FIND_SERVICE_UID;
    }

    dap_chain_net_t * l_net = l_net_name ? dap_chain_net_by_name(l_net_name) : NULL;
    if(!l_net) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_CAN_NOT_FIND_NET,
                               "Can't find net '%s'", l_net_name);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_CAN_NOT_FIND_NET;
    }

    dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, c_wallets_path, NULL);
    if(!l_wallet) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_CAN_NOT_OPEN_WALLET, "Can't open wallet '%s'", l_wallet_str);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_CAN_NOT_OPEN_WALLET;
    }

    dap_enc_key_t *l_key_from = dap_chain_wallet_get_key(l_wallet, 0);
    dap_pkey_t *l_wallet_pkey = dap_pkey_from_enc_key(l_key_from);

    const char *l_native_ticker = l_net->pub.native_ticker;
    if (!l_native_ticker){
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_CAN_NOT_FIND_NATIVE_TICKER_IN_NET,
                               "Can't find native ticker for net %s", l_net->pub.name);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_CAN_NOT_FIND_NATIVE_TICKER_IN_NET;
    }
    dap_ledger_t *l_ledger = dap_ledger_by_net_name(l_net->pub.name);
    if (!l_ledger){
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_CAN_NOT_FIND_LEDGER_FOR_NET, "Can't find ledger for net %s", l_net->pub.name);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_CAN_NOT_FIND_LEDGER_FOR_NET;
    }

//    dap_string_t *l_reply_str = dap_string_new("");
    json_object *l_jobj_tx_list_cond_outs = json_object_new_array();
    dap_list_t *l_tx_list = NULL;

    dap_chain_net_get_tx_all(l_net, TX_SEARCH_TYPE_NET, s_tx_is_srv_pay_check, &l_tx_list);
    size_t l_tx_count = 0;
    uint256_t l_total_value = {};
    for (dap_list_t *it = l_tx_list; it; it = it->next) {
        tx_check_args_t *l_data_tx = (tx_check_args_t*)it->data;
        dap_chain_datum_tx_t *l_tx = l_data_tx->tx;
        int l_prev_cond_idx = 0;
        dap_chain_tx_out_cond_t *l_out_cond = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY , &l_prev_cond_idx);
        if (!l_out_cond || l_out_cond->header.srv_uid.uint64 != l_srv_uid.uint64 || IS_ZERO_256(l_out_cond->header.value))
            continue;

        if (dap_ledger_tx_hash_is_used_out_item(l_ledger, &l_data_tx->tx_hash, l_prev_cond_idx, NULL)) {
            continue;
        }

        const char *l_tx_ticker = dap_ledger_tx_get_token_ticker_by_hash(l_ledger, &l_data_tx->tx_hash);
        if (!l_tx_ticker) {
            continue;
        }
        if (strcmp(l_native_ticker, l_tx_ticker)) {
            continue;
        }

        // Check sign
        dap_hash_fast_t l_owner_tx_hash = dap_ledger_get_first_chain_tx_hash(l_ledger, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY, &l_data_tx->tx_hash);
        dap_chain_datum_tx_t *l_owner_tx = dap_hash_fast_is_blank(&l_owner_tx_hash)
            ? l_tx
            : dap_ledger_tx_find_by_hash(l_ledger, &l_owner_tx_hash);

        if (!l_owner_tx)
            continue;
        dap_chain_tx_sig_t *l_owner_tx_sig = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(l_owner_tx, NULL, NULL, TX_ITEM_TYPE_SIG, NULL);
        dap_sign_t *l_owner_sign = dap_chain_datum_tx_item_sig_get_sign((dap_chain_tx_sig_t *)l_owner_tx_sig);


        if (!dap_pkey_compare_with_sign(l_wallet_pkey, l_owner_sign)) {
            continue;
        }

        char *l_remain_datoshi_str = NULL;
        char *l_remain_coins_str = NULL;
        char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
        dap_chain_hash_fast_to_str(&l_data_tx->tx_hash, l_hash_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
        l_remain_coins_str = dap_chain_balance_coins_print(l_out_cond->header.value);
        l_remain_datoshi_str = dap_chain_balance_datoshi_print(l_out_cond->header.value);
        json_object *l_jobj_hash = json_object_new_string(l_hash_str);
        json_object *l_jobj_remain = json_object_new_object();
        json_object *l_jobj_remain_coins = json_object_new_string(l_remain_coins_str);
        json_object *l_jobj_remain_datoshi = json_object_new_string(l_remain_datoshi_str);
        json_object_object_add(l_jobj_remain, "coins", l_jobj_remain_coins);
        json_object_object_add(l_jobj_remain, "datoshi", l_jobj_remain_datoshi);
        json_object *l_jobj_native_ticker = json_object_new_string(l_native_ticker);
        json_object *l_jobj_tx = json_object_new_object();
        json_object_object_add(l_jobj_tx, "hash", l_jobj_hash);
        json_object_object_add(l_jobj_tx, "remain", l_jobj_remain);
        json_object_object_add(l_jobj_tx, "ticker", l_jobj_native_ticker);
        json_object_array_add(l_jobj_tx_list_cond_outs, l_jobj_tx);
        l_tx_count++;
        SUM_256_256(l_total_value, l_out_cond->header.value, &l_total_value);
    }
    char *l_total_datoshi_str = dap_chain_balance_coins_print(l_total_value);
    char *l_total_coins_str = dap_chain_balance_datoshi_print(l_total_value);
    json_object *l_jobj_total = json_object_new_object();
    json_object *l_jobj_total_datoshi = json_object_new_string(l_total_datoshi_str);
    json_object *l_jobj_total_coins = json_object_new_string(l_total_coins_str);
    json_object *l_jobj_native_ticker = json_object_new_string(l_native_ticker);
    json_object_object_add(l_jobj_total, "datoshi", l_jobj_total_datoshi);
    json_object_object_add(l_jobj_total, "coins", l_jobj_total_coins);
    json_object_object_add(l_jobj_total, "ticker", l_jobj_native_ticker);
    json_object_object_add(l_jobj_total, "tx_count", json_object_new_uint64(l_tx_count));
    json_object *l_jobj_ret = json_object_new_object();
    json_object_object_add(l_jobj_ret, "transactions_out_cond", l_jobj_tx_list_cond_outs);
    json_object_object_add(l_jobj_ret, "total", l_jobj_total);
    dap_list_free_full(l_tx_list, NULL);
    json_object_array_add(*a_json_arr_reply, l_jobj_ret);
    DAP_DEL_Z(l_wallet_pkey);
    dap_chain_wallet_close(l_wallet);
    return DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_OK;
}
