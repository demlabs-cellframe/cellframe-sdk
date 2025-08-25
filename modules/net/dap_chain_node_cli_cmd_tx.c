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
#include <stdint.h>
#include <string.h>
#include "json_object.h"
#include "uthash.h"
#include "dap_cli_server.h"
#include "dap_common.h"
#include "dap_enc_base58.h"
#include "dap_strfuncs.h"
#include "dap_string.h"
#include "dap_list.h"
#include "dap_hash.h"
#include "dap_time.h"
#include "dap_chain_cell.h"
#include "dap_chain_datum.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_datum_decree.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_datum_anchor.h"
#include "dap_chain_node_cli_cmd_tx.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_net_decree.h"
#include "dap_chain_mempool.h"
#include "dap_math_convert.h"
#include "dap_json_rpc_errors.h"
#include "dap_enc_base64.h"

#include "dap_chain_wallet_cache.h"

#define LOG_TAG "chain_node_cli_cmd_tx"



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

bool s_dap_chain_datum_tx_out_data(json_object* a_json_arr_reply,
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
    json_object* json_arr_items = json_object_new_array();
    bool l_spent = false;
    byte_t *l_item; size_t l_size; int i, l_out_idx = -1;
    TX_ITEM_ITER_TX_TYPE(l_item, TX_ITEM_TYPE_OUT_ALL, l_size, i, a_datum) {
        ++l_out_idx;
        dap_hash_fast_t l_spender = { };
        if ( dap_ledger_tx_hash_is_used_out_item(a_ledger, a_tx_hash, l_out_idx, &l_spender) ) {
            char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE] = { '\0' };
            dap_hash_fast_to_str(&l_spender, l_hash_str, sizeof(l_hash_str));
            json_object * l_json_obj_datum = json_object_new_object();
            json_object_object_add(l_json_obj_datum, a_version == 1 ? "OUT - " : "out", json_object_new_int(l_out_idx));
            json_object_object_add(l_json_obj_datum, a_version == 1 ? "is spent by tx" : "spent_by_tx", json_object_new_string(l_hash_str));
            json_object_array_add(json_arr_items, l_json_obj_datum);
            l_spent = true;
        }
    }
    json_object_object_add(json_obj_out, a_version == 1 ? "Spent OUTs" : "spent_outs", json_arr_items);
    json_object_object_add(json_obj_out, a_version == 1 ? "all OUTs yet unspent" : "all_outs_yet_unspent", l_spent ? json_object_new_string("no") : json_object_new_string("yes"));
    return true;
}

json_object *dap_db_tx_history_to_json(json_object* a_json_arr_reply,
                                        dap_chain_hash_fast_t* a_tx_hash,
                                        dap_hash_fast_t * l_atom_hash,
                                        dap_chain_datum_tx_t * l_tx,
                                        dap_chain_t * a_chain, 
                                        const char *a_hash_out_type, 
                                        dap_chain_datum_iter_t *a_datum_iter,
                                        int l_ret_code,
                                        bool *accepted_tx,
                                        bool brief_out,
                                        int a_version)
{
    const char *l_tx_token_ticker = NULL;
    const char *l_tx_token_description = NULL;
    json_object* json_obj_datum = json_object_new_object();
    if (!json_obj_datum) {
        return NULL;
    }

    dap_ledger_t *l_ledger = dap_chain_net_by_id(a_chain->net_id)->pub.ledger;
    l_tx_token_ticker = a_datum_iter ? a_datum_iter->token_ticker
                                     : dap_ledger_tx_get_token_ticker_by_hash(l_ledger, a_tx_hash);
    if (l_tx_token_ticker) {
        json_object_object_add(json_obj_datum, "status", json_object_new_string("ACCEPTED"));
        l_tx_token_description = dap_ledger_get_description_by_ticker(l_ledger, l_tx_token_ticker);
        *accepted_tx = true;
    } else {
        json_object_object_add(json_obj_datum, "status", json_object_new_string("DECLINED"));
        *accepted_tx = false;
    }

    if (l_atom_hash) {
        const char *l_atom_hash_str = dap_strcmp(a_hash_out_type, "hex")
                            ? dap_enc_base58_encode_hash_to_str_static(l_atom_hash)
                            : dap_chain_hash_fast_to_str_static(l_atom_hash);
        json_object_object_add(json_obj_datum, "atom_hash", json_object_new_string(l_atom_hash_str));

        dap_chain_atom_iter_t *l_iter = a_chain->callback_atom_iter_create(a_chain, a_chain->active_cell_id, l_atom_hash);
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
    
    if (l_tx_token_description) 
        json_object_object_add(json_obj_datum, "token_description", json_object_new_string(l_tx_token_description));

    json_object_object_add(json_obj_datum, "ret_code", json_object_new_int(l_ret_code));
    json_object_object_add(json_obj_datum, "ret_code_str", json_object_new_string(dap_ledger_check_error_str(l_ret_code)));

    dap_chain_net_srv_uid_t uid;
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
                      dap_chain_net_t * l_net,
                      int a_version)

{
    if (!a_chain->callback_datum_find_by_hash) {
        log_it(L_WARNING, "Not defined callback_datum_find_by_hash for chain \"%s\"", a_chain->name);
        return NULL;
    }

    int l_ret_code = 0;
    bool accepted_tx;
    dap_hash_fast_t l_atom_hash = {0};
    //search tx
    dap_chain_datum_t *l_datum = a_chain->callback_datum_find_by_hash(a_chain, a_tx_hash, &l_atom_hash, &l_ret_code);
    dap_chain_datum_tx_t *l_tx = l_datum  && l_datum->header.type_id == DAP_CHAIN_DATUM_TX ?
                                 (dap_chain_datum_tx_t *)l_datum->data : NULL;

    if (l_tx) {
        return dap_db_tx_history_to_json(a_json_arr_reply, a_tx_hash, &l_atom_hash,l_tx, a_chain, a_hash_out_type, NULL, l_ret_code, &accepted_tx, false, a_version);
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
                              int a_ret_code, dap_chain_tx_tag_action_type_t a_action, dap_chain_net_srv_uid_t a_uid)
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
        json_object *l_corr_object = NULL, *l_cond_recv_object = NULL, *l_cond_send_object = NULL, 
                    *l_possible_recv_from_cond_object = NULL;
           
        dap_chain_addr_t *l_src_addr = NULL;
        bool l_base_tx = false, l_reward_collect = false;
        const char *l_noaddr_token = NULL;

        dap_hash_fast_t l_tx_hash = l_from_cache ? *l_wallet_cache_iter->cur_hash : *l_datum_iter->cur_hash;
        const char *l_src_token = l_from_cache ? l_wallet_cache_iter->token_ticker : l_datum_iter->token_ticker;
        int l_ret_code = l_from_cache ? l_wallet_cache_iter->ret_code : l_datum_iter->ret_code;
        uint32_t l_action = l_from_cache ? l_wallet_cache_iter->action : l_datum_iter->action;
        dap_chain_net_srv_uid_t l_uid = l_from_cache ? l_wallet_cache_iter->uid : l_datum_iter->uid;
        dap_hash_fast_t l_atom_hash = l_from_cache ? *l_wallet_cache_iter->cur_atom_hash : *l_datum_iter->cur_atom_hash;

        int l_src_subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_UNDEFINED;
        uint8_t *l_tx_item = NULL;
        size_t l_size; int i, q = 0;
        // Inputs iteration
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

    bool accepted_tx;
    *a_json_obj_datum = dap_db_tx_history_to_json(a_json_arr_reply, &l_ttx_hash, NULL, l_tx, a_chain, a_hash_out_type, a_datum_iter, 0, &accepted_tx, a_out_brief, a_version);
    if (!*a_json_obj_datum) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return 2;
    }
    if (accepted_tx) {
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
    enum { CMD_NONE, CMD_LIST, CMD_TX_INFO };
    int arg_index = 1;
    const char *l_net_str = NULL;
    const char *l_tx_hash_str = NULL;
    const char *l_hash_out_type = NULL;

    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR, "invalid parameter -H, valid values: -H <hex | base58>");
        return DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR;
    }

    //switch ledger params list | tx | info
    int l_cmd = CMD_NONE;
    if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "list", NULL)){
        l_cmd = CMD_LIST;
    } else if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "info", NULL))
        l_cmd = CMD_TX_INFO;

    bool l_is_all = dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-all", NULL);

    arg_index++;

    if(l_cmd == CMD_LIST){
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
    } else if (l_cmd == CMD_TX_INFO){
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-hash", &l_tx_hash_str);
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_str);
        bool l_need_sign  = dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-need_sign", NULL);
        bool l_unspent_flag = dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-unspent", NULL);
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
            byte_t *l_item; size_t l_size; int index, l_out_idx = 0;
            json_object* json_arr_items = json_object_new_array();
            TX_ITEM_ITER_TX_TYPE(l_item, TX_ITEM_TYPE_OUT_ALL, l_size, index, l_datum_tx) {
                dap_hash_fast_t l_spender = { };
                if ( dap_ledger_tx_hash_is_used_out_item(l_net->pub.ledger, l_tx_hash, l_out_idx, &l_spender) ) {
                    l_all_outs_unspent = false;
                    char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE] = { '\0' };
                    dap_hash_fast_to_str(&l_spender, l_hash_str, sizeof(l_hash_str));
                    json_object * l_json_obj_datum = json_object_new_object();
                    json_object_object_add(l_json_obj_datum, "out_idx", json_object_new_int(l_out_idx));
                    json_object_object_add(l_json_obj_datum, "spent_by_tx", json_object_new_string(l_hash_str));
                    json_object_array_add(json_arr_items, l_json_obj_datum);
                }
                ++l_out_idx;
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
                    dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t*)item);
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
    }
    else{
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR, "Command 'ledger' requires parameter 'list' or 'info'", l_tx_hash_str);
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

/* Decree section */

/**
 * @brief
 * sign data (datum_decree) by certificates (1 or more)
 * successful count of signes return in l_sign_counter
 * @param l_certs - array with certificates loaded from dcert file
 * @param l_datum_token - updated pointer for l_datum_token variable after realloc
 * @param l_certs_count - count of certificate
 * @param l_datum_data_offset - offset of datum
 * @param l_sign_counter - counter of successful data signing operation
 * @return dap_chain_datum_token_t*
 */
static dap_chain_datum_anchor_t * s_sign_anchor_in_cycle(dap_cert_t ** a_certs, dap_chain_datum_anchor_t *a_datum_anchor,
                    size_t a_certs_count, size_t *a_total_sign_count)
{
    size_t l_cur_sign_offset = a_datum_anchor->header.data_size + a_datum_anchor->header.signs_size;
    size_t l_total_signs_size = a_datum_anchor->header.signs_size, l_total_sign_count = 0;

    for(size_t i = 0; i < a_certs_count; i++)
    {
        dap_sign_t * l_sign = dap_cert_sign(a_certs[i],  a_datum_anchor, sizeof(dap_chain_datum_anchor_t) + a_datum_anchor->header.data_size);

        if (l_sign) {
            size_t l_sign_size = dap_sign_get_size(l_sign);
            dap_chain_datum_anchor_t *l_new_anchor
                = DAP_REALLOC_RET_VAL_IF_FAIL(a_datum_anchor, sizeof(dap_chain_datum_anchor_t) + l_cur_sign_offset + l_sign_size, NULL, l_sign);
            a_datum_anchor = l_new_anchor;
            memcpy((byte_t*)a_datum_anchor->data_n_sign + l_cur_sign_offset, l_sign, l_sign_size);
            l_total_signs_size += l_sign_size;
            l_cur_sign_offset += l_sign_size;
            a_datum_anchor->header.signs_size = l_total_signs_size;
            DAP_DELETE(l_sign);
            log_it(L_DEBUG,"<-- Signed with '%s'", a_certs[i]->name);
            l_total_sign_count++;
        }
    }

    *a_total_sign_count = l_total_sign_count;
    return a_datum_anchor;
}

// Decree commands handlers
int cmd_decree(int a_argc, char **a_argv, void **a_str_reply, UNUSED_ARG int a_version)
{
    enum { CMD_NONE=0, CMD_CREATE, CMD_SIGN, CMD_ANCHOR, CMD_FIND, CMD_INFO };
    enum { TYPE_NONE=0, TYPE_COMMON, TYPE_SERVICE};
    enum { SUBTYPE_NONE=0, SUBTYPE_FEE, SUBTYPE_OWNERS, SUBTYPE_MIN_OWNERS, SUBTYPE_IP_BAN};
    int arg_index = 1;
    const char *l_net_str = NULL;
    const char * l_chain_str = NULL;
    const char * l_decree_chain_str = NULL;
    const char * l_certs_str = NULL;
    dap_cert_t ** l_certs = NULL;
    size_t l_certs_count = 0;
    dap_chain_net_t * l_net = NULL;
    dap_chain_t * l_chain = NULL;
    dap_chain_t * l_decree_chain = NULL;

    const char * l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "invalid parameter -H, valid values: -H <hex | base58>");
        return -1;
    }

    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_str);
    // Select chain network
    if(!l_net_str) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "command requires parameter '-net'");
        return -2;
    } else {
        if((l_net = dap_chain_net_by_name(l_net_str)) == NULL) { // Can't find such network
            dap_cli_server_cmd_set_reply_text(a_str_reply,
                    "command requires parameter '-net' to be valid chain network name");
            return -3;
        }
    }

    int l_cmd = CMD_NONE;
    if (dap_cli_server_cmd_find_option_val(a_argv, 1, 2, "create", NULL))
        l_cmd = CMD_CREATE;
    else if (dap_cli_server_cmd_find_option_val(a_argv, 1, 2, "sign", NULL))
        l_cmd = CMD_SIGN;
    else if (dap_cli_server_cmd_find_option_val(a_argv, 1, 2, "anchor", NULL))
        l_cmd = CMD_ANCHOR;
    else if (dap_cli_server_cmd_find_option_val(a_argv, 1, 2, "find", NULL))
        l_cmd = CMD_FIND;
    else if (dap_cli_server_cmd_find_option_val(a_argv, 1, 2, "info", NULL))
        l_cmd = CMD_INFO;

    if (l_cmd != CMD_FIND && l_cmd != CMD_INFO) {
        // Public certifiacte of condition owner
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-certs", &l_certs_str);
        if (!l_certs_str) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "decree create requires parameter '-certs'");
            return -106;
        }
        dap_cert_parse_str_list(l_certs_str, &l_certs, &l_certs_count);
    }

    switch (l_cmd)
    {
    case CMD_CREATE:{
        if(!l_certs_count) {
            dap_cli_server_cmd_set_reply_text(a_str_reply,
                    "decree create command requres at least one valid certificate to sign the decree");
            return -106;
        }
        int l_type = TYPE_NONE;
        if (dap_cli_server_cmd_find_option_val(a_argv, 2, 3, "common", NULL))
            l_type = TYPE_COMMON;
        else if (dap_cli_server_cmd_find_option_val(a_argv, 2, 3, "service", NULL))
            l_type = TYPE_SERVICE;

        dap_chain_datum_decree_t *l_datum_decree = NULL;

        if (l_type == TYPE_COMMON){
            // Common decree create
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-chain", &l_chain_str);

            // Search chain
            if(l_chain_str) {
                l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_str);
                if (l_chain == NULL) {
                    return dap_cli_server_cmd_set_reply_text(a_str_reply, "Invalid '-chain' parameter \"%s\", not found in net %s\n"
                                                                   "Available chain with decree support:\n\t\"%s\"\n",
                                                                   l_chain_str, l_net_str,
                                                                   dap_chain_net_get_chain_by_chain_type(l_net, CHAIN_TYPE_DECREE)->name),
                            -103;
                } else if (l_chain != dap_chain_net_get_chain_by_chain_type(l_net, CHAIN_TYPE_DECREE)){ // check chain to support decree
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Chain %s don't support decree", l_chain->name);
                    return -104;
                }
            }else if((l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_DECREE)) == NULL) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't find chain with decree support.");
                return -105;
            }

            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-decree_chain", &l_decree_chain_str);

            // Search chain
            if(l_decree_chain_str) {
                l_decree_chain = dap_chain_net_get_chain_by_name(l_net, l_decree_chain_str);
                if (l_decree_chain == NULL) {
                    dap_string_t *l_reply = dap_string_new("");
                    dap_string_append_printf(l_reply, "Invalid '-chain' parameter \"%s\", not found in net %s\n"
                                                      "Available chains:",
                                                      l_chain_str, l_net_str);
                    dap_chain_t *l_chain;
                    DL_FOREACH(l_net->pub.chains, l_chain) {
                        dap_string_append_printf(l_reply, "\n\t%s", l_chain->name);
                    }
                    char *l_str_reply = dap_string_free(l_reply, false);
                    return dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_str_reply), DAP_DELETE(l_str_reply), -103;
                }
            }else {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "decree requires parameter -decree_chain.");
                return -105;
            }

            dap_tsd_t *l_tsd = NULL;
            dap_cert_t **l_new_certs = NULL;
            size_t l_new_certs_count = 0, l_total_tsd_size = 0;
            dap_list_t *l_tsd_list = NULL;

            int l_subtype = SUBTYPE_NONE;
            const char *l_param_value_str = NULL;
            const char *l_param_addr_str = NULL;
            if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-fee", &l_param_value_str)){
                l_subtype = SUBTYPE_FEE;
                if (!dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-to_addr", &l_param_addr_str)){
                    if (dap_chain_addr_is_blank(&l_net->pub.fee_addr)) {
                        dap_cli_server_cmd_set_reply_text(a_str_reply, "Use -to_addr parameter to set net fee");
                        return -111;
                    }
                }else{
                    l_total_tsd_size += sizeof(dap_tsd_t) + sizeof(dap_chain_addr_t);
                    l_tsd = DAP_NEW_Z_SIZE(dap_tsd_t, l_total_tsd_size);
                    if (!l_tsd) {
                        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                        dap_list_free_full(l_tsd_list, NULL);
                        return -1;
                    }
                    l_tsd->type = DAP_CHAIN_DATUM_DECREE_TSD_TYPE_FEE_WALLET;
                    l_tsd->size = sizeof(dap_chain_addr_t);
                    dap_chain_addr_t *l_addr = dap_chain_addr_from_str(l_param_addr_str);
                    memcpy(l_tsd->data, l_addr, sizeof(dap_chain_addr_t));
                    l_tsd_list = dap_list_append(l_tsd_list, l_tsd);
                }

                l_total_tsd_size += sizeof(dap_tsd_t) + sizeof(uint256_t);
                l_tsd = DAP_NEW_Z_SIZE(dap_tsd_t, l_total_tsd_size);
                if (!l_tsd) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    dap_list_free_full(l_tsd_list, NULL);
                    return -1;
                }
                l_tsd->type = DAP_CHAIN_DATUM_DECREE_TSD_TYPE_FEE;
                l_tsd->size = sizeof(uint256_t);
                *(uint256_t*)(l_tsd->data) = dap_uint256_scan_uninteger(l_param_value_str);
                l_tsd_list = dap_list_append(l_tsd_list, l_tsd);
            }else if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-new_certs", &l_param_value_str)){
                l_subtype = SUBTYPE_OWNERS;
                dap_cert_parse_str_list(l_param_value_str, &l_new_certs, &l_new_certs_count);

                dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
                uint16_t l_min_signs = dap_chain_net_get_net_decree(l_net)->min_num_of_owners;
                if (l_new_certs_count < l_min_signs) {
                    log_it(L_WARNING,"Number of new certificates is less than minimum owner number.");
                    return -106;
                }

                size_t l_failed_certs = 0;
                for (size_t i=0;i<l_new_certs_count;i++){
                    dap_pkey_t *l_pkey = dap_cert_to_pkey(l_new_certs[i]);
                    if(!l_pkey)
                    {
                        log_it(L_WARNING,"New cert [%zu] have no public key.", i);
                        l_failed_certs++;
                        continue;
                    }
                    l_tsd = dap_tsd_create(DAP_CHAIN_DATUM_DECREE_TSD_TYPE_OWNER, l_pkey, sizeof(dap_pkey_t) + (size_t)l_pkey->header.size);
                    DAP_DELETE(l_pkey);
                    l_tsd_list = dap_list_append(l_tsd_list, l_tsd);
                    l_total_tsd_size += sizeof(dap_tsd_t) + (size_t)l_tsd->size;
                }
                if(l_failed_certs)
                {
                    dap_list_free_full(l_tsd_list, NULL);
                    return -108;
                }
            }else if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-signs_verify", &l_param_value_str)) {
                l_subtype = SUBTYPE_MIN_OWNERS;
                uint256_t l_new_num_of_owners = dap_uint256_scan_uninteger(l_param_value_str);
                if (IS_ZERO_256(l_new_num_of_owners)) {
                    log_it(L_WARNING, "The minimum number of owners can't be zero");
                    dap_list_free_full(l_tsd_list, NULL);
                    return -112;
                }
                dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
                uint256_t l_owners = GET_256_FROM_64(dap_chain_net_get_net_decree(l_net)->num_of_owners);
                if (compare256(l_new_num_of_owners, l_owners) > 0) {
                    log_it(L_WARNING, "The minimum number of owners is greater than the total number of owners.");
                    dap_list_free_full(l_tsd_list, NULL);
                    return -110;
                }

                l_total_tsd_size = sizeof(dap_tsd_t) + sizeof(uint256_t);
                l_tsd = DAP_NEW_Z_SIZE(dap_tsd_t, l_total_tsd_size);
                if (!l_tsd) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    dap_list_free_full(l_tsd_list, NULL);
                    return -1;
                }
                l_tsd->type = DAP_CHAIN_DATUM_DECREE_TSD_TYPE_MIN_OWNER;
                l_tsd->size = sizeof(uint256_t);
                *(uint256_t *) (l_tsd->data) = l_new_num_of_owners;
                l_tsd_list = dap_list_append(l_tsd_list, l_tsd);
            } else{
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Decree subtype fail.");
                return -111;
            }

            if (l_subtype == DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_OWNERS ||
                l_subtype == DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_OWNERS_MIN)
            {
                if (l_decree_chain->id.uint64 != l_chain->id.uint64){
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Decree subtype %s not suppurted by chain %s",
                                                      dap_chain_datum_decree_subtype_to_str(l_subtype), l_decree_chain_str);
                    return -107;
                }
            } else if (l_decree_chain->id.uint64 == l_chain->id.uint64){
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Decree subtype %s not suppurted by chain %s",
                                                  dap_chain_datum_decree_subtype_to_str(l_subtype), l_decree_chain_str);
                return -107;
            }

            l_datum_decree = DAP_NEW_Z_SIZE(dap_chain_datum_decree_t, sizeof(dap_chain_datum_decree_t) + l_total_tsd_size);
            l_datum_decree->decree_version = DAP_CHAIN_DATUM_DECREE_VERSION;
            l_datum_decree->header.ts_created = dap_time_now();
            l_datum_decree->header.type = l_type;
            l_datum_decree->header.common_decree_params.net_id = dap_chain_net_id_by_name(l_net_str);
            l_datum_decree->header.common_decree_params.chain_id = l_decree_chain->id;
            l_datum_decree->header.common_decree_params.cell_id = *dap_chain_net_get_cur_cell(l_net);
            l_datum_decree->header.sub_type = l_subtype;
            l_datum_decree->header.data_size = l_total_tsd_size;
            l_datum_decree->header.signs_size = 0;

            size_t l_data_tsd_offset = 0;
            for ( dap_list_t* l_iter=dap_list_first(l_tsd_list); l_iter; l_iter=l_iter->next){
                dap_tsd_t * l_b_tsd = (dap_tsd_t *) l_iter->data;
                size_t l_tsd_size = dap_tsd_size(l_b_tsd);
                memcpy((byte_t*)l_datum_decree->data_n_signs + l_data_tsd_offset, l_b_tsd, l_tsd_size);
                l_data_tsd_offset += l_tsd_size;
            }
            dap_list_free_full(l_tsd_list, NULL);

        }else if (l_type == TYPE_SERVICE) {

        }else{
            dap_cli_server_cmd_set_reply_text(a_str_reply, "not found decree type (common or service)");
            return -107;
        }

        // Sign decree
        size_t l_total_signs_success = 0;
        if (l_certs_count)
            l_datum_decree = dap_chain_datum_decree_sign_in_cycle(l_certs, l_datum_decree, l_certs_count, &l_total_signs_success);

        if (!l_datum_decree || l_total_signs_success == 0){
            dap_cli_server_cmd_set_reply_text(a_str_reply,
                        "Decree creation failed. Successful count of certificate signing is 0");
                return -108;
        }

        // Create datum
        dap_chain_datum_t * l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_DECREE,
                                                             l_datum_decree,
                                                             sizeof(*l_datum_decree) + l_datum_decree->header.data_size +
                                                             l_datum_decree->header.signs_size);
        DAP_DELETE(l_datum_decree);
        char *l_key_str_out = dap_chain_mempool_datum_add(l_datum, l_chain, l_hash_out_type);
        DAP_DELETE(l_datum);
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Datum %s is%s placed in datum pool",
                                          l_key_str_out ? l_key_str_out : "",
                                          l_key_str_out ? "" : " not");
        break;
    }
    case CMD_SIGN:{
        if(!l_certs_count) {
            dap_cli_server_cmd_set_reply_text(a_str_reply,
                    "decree sign command requres at least one valid certificate to sign");
            return -106;
        }

        const char * l_datum_hash_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-datum", &l_datum_hash_str);
        if(l_datum_hash_str) {
            char * l_datum_hash_hex_str = NULL;
            char * l_datum_hash_base58_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-chain", &l_chain_str);
            // Search chain
            if(l_chain_str) {
                l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_str);
                if (l_chain == NULL) {
                    return dap_cli_server_cmd_set_reply_text(a_str_reply, "Invalid '-chain' parameter \"%s\", not found in net %s\n"
                                                                          "Available chain with decree support:\n\t\"%s\"\n",
                                                                          l_chain_str, l_net_str,
                                                                          dap_chain_net_get_chain_by_chain_type(l_net, CHAIN_TYPE_DECREE)->name),
                            -103;
                } else if (l_chain != dap_chain_net_get_chain_by_chain_type(l_net, CHAIN_TYPE_DECREE)){ // check chain to support decree
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Chain %s don't support decree", l_chain->name);
                    return -104;
                }
            }else if((l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_DECREE)) == NULL) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't find chain with decree support.");
                return -105;
            }

            char * l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool_new(l_chain);
            if(!l_gdb_group_mempool) {
                l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool_by_chain_type(l_net, CHAIN_TYPE_DECREE);
            }
            // datum hash may be in hex or base58 format
            if(!dap_strncmp(l_datum_hash_str, "0x", 2) || !dap_strncmp(l_datum_hash_str, "0X", 2)) {
                l_datum_hash_hex_str = dap_strdup(l_datum_hash_str);
                l_datum_hash_base58_str = dap_enc_base58_from_hex_str_to_str(l_datum_hash_str);
            } else {
                l_datum_hash_hex_str = dap_enc_base58_to_hex_str_from_str(l_datum_hash_str);
                l_datum_hash_base58_str = dap_strdup(l_datum_hash_str);
            }

            const char *l_datum_hash_out_str;
            if(!dap_strcmp(l_hash_out_type,"hex"))
                l_datum_hash_out_str = l_datum_hash_hex_str;
            else
                l_datum_hash_out_str = l_datum_hash_base58_str;

            log_it(L_DEBUG, "Requested to sign decree creation %s in gdb://%s with certs %s",
                    l_gdb_group_mempool, l_datum_hash_hex_str, l_certs_str);

            dap_chain_datum_t * l_datum = NULL;
            size_t l_datum_size = 0;
            if((l_datum = (dap_chain_datum_t*) dap_global_db_get_sync(l_gdb_group_mempool,
                    l_datum_hash_hex_str, &l_datum_size, NULL, NULL )) != NULL) {
                // Check if its decree creation
                if(l_datum->header.type_id == DAP_CHAIN_DATUM_DECREE) {
                    dap_chain_datum_decree_t *l_datum_decree = DAP_DUP_SIZE((dap_chain_datum_decree_t*)l_datum->data, l_datum->header.data_size);
                    DAP_DELETE(l_datum);

                    // Sign decree
                    size_t l_total_signs_success = 0;
                    if (l_certs_count)
                        l_datum_decree = dap_chain_datum_decree_sign_in_cycle(l_certs, l_datum_decree, l_certs_count, &l_total_signs_success);

                    if (!l_datum_decree || l_total_signs_success == 0){
                        dap_cli_server_cmd_set_reply_text(a_str_reply,
                                    "Decree creation failed. Successful count of certificate signing is 0");
                            return -108;
                    }
                    size_t l_decree_size = dap_chain_datum_decree_get_size(l_datum_decree);
                    dap_chain_datum_t * l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_DECREE,
                                                                         l_datum_decree, l_decree_size);
                    DAP_DELETE(l_datum_decree);

                    char *l_key_str_out = dap_chain_mempool_datum_add(l_datum, l_chain, l_hash_out_type);
                    DAP_DELETE(l_datum);
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Datum %s is%s placed in datum pool",
                                                      l_key_str_out ? l_key_str_out : "",
                                                      l_key_str_out ? "" : " not");

                    }else{
                    dap_cli_server_cmd_set_reply_text(a_str_reply,
                            "Error! Wrong datum type. decree sign only decree datum");
                    return -61;
                }
            }else{
                dap_cli_server_cmd_set_reply_text(a_str_reply,
                        "decree sign can't find datum with %s hash in the mempool of %s:%s",l_datum_hash_out_str,l_net? l_net->pub.name: "<undefined>",
                        l_chain?l_chain->name:"<undefined>");
                return -5;
            }
            DAP_DEL_MULTY(l_datum_hash_hex_str, l_datum_hash_base58_str);
        } else {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "decree sign need -datum <datum hash> argument");
            return -2;
        }
        break;
    }
    case CMD_ANCHOR:{
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-chain", &l_chain_str);

        // Search chain
        if(l_chain_str) {
            l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_str);
            if (l_chain == NULL) {
                return dap_cli_server_cmd_set_reply_text(a_str_reply, "Invalid '-chain' parameter \"%s\", not found in net %s\n"
                                                                      "Available chain with anchor support:\n\t\"%s\"\n",
                                                                      l_chain_str, l_net_str,
                                                                      dap_chain_net_get_chain_by_chain_type(l_net, CHAIN_TYPE_ANCHOR)->name),
                        -103;
            } else if (l_chain != dap_chain_net_get_chain_by_chain_type(l_net, CHAIN_TYPE_ANCHOR)){ // check chain to support decree
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Chain %s don't support decree", l_chain->name);
                return -104;
            }
        }else if((l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_ANCHOR)) == NULL) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't find chain with default anchor support.");
            return -105;
        }

        dap_chain_datum_anchor_t *l_datum_anchor = NULL;
        dap_hash_fast_t l_hash = {};
        const char * l_datum_hash_str = NULL;
        if (!dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-datum", &l_datum_hash_str))
        {
            dap_cli_server_cmd_set_reply_text(a_str_reply,
                        "Anchor creation failed. Cmd decree create anchor must contain -datum parameter.");
                return -107;
        }
        if(l_datum_hash_str) {
            dap_chain_hash_fast_from_str(l_datum_hash_str, &l_hash);
        }

        // Pack data into TSD
        dap_tsd_t *l_tsd = NULL;
        l_tsd = dap_tsd_create(DAP_CHAIN_DATUM_ANCHOR_TSD_TYPE_DECREE_HASH, &l_hash, sizeof(dap_hash_fast_t));
        if(!l_tsd)
        {
            dap_cli_server_cmd_set_reply_text(a_str_reply,
                        "Anchor creation failed. Memory allocation fail.");
                return -107;
        }

        // Create anchor datum
        l_datum_anchor = DAP_NEW_Z_SIZE(dap_chain_datum_anchor_t, sizeof(dap_chain_datum_anchor_t) + dap_tsd_size(l_tsd));
        l_datum_anchor->header.data_size = dap_tsd_size(l_tsd);
        l_datum_anchor->header.ts_created = dap_time_now();
        memcpy(l_datum_anchor->data_n_sign, l_tsd, dap_tsd_size(l_tsd));

        DAP_DEL_Z(l_tsd);

        // Sign anchor
        size_t l_total_signs_success = 0;
        if (l_certs_count)
            l_datum_anchor = s_sign_anchor_in_cycle(l_certs, l_datum_anchor, l_certs_count, &l_total_signs_success);

        if (!l_datum_anchor || l_total_signs_success == 0){
            dap_cli_server_cmd_set_reply_text(a_str_reply,
                        "Anchor creation failed. Successful count of certificate signing is 0");
            return DAP_DELETE(l_datum_anchor), -108;
        }

        // Create datum
        dap_chain_datum_t * l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_ANCHOR,
                                                             l_datum_anchor,
                                                             sizeof(*l_datum_anchor) + l_datum_anchor->header.data_size +
                                                             l_datum_anchor->header.signs_size);
        DAP_DELETE(l_datum_anchor);
        char *l_key_str_out = dap_chain_mempool_datum_add(l_datum, l_chain, l_hash_out_type);
        DAP_DELETE(l_datum);
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Datum %s is%s placed in datum pool",
                                          l_key_str_out ? l_key_str_out : "",
                                          l_key_str_out ? "" : " not");
        break;
    }
    case CMD_FIND: {
        const char *l_hash_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-hash", &l_hash_str);
        if (!l_hash_str) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'decree find' requiers parameter '-hash'");
            return -110;
        }
        dap_hash_fast_t l_datum_hash;
        if (dap_chain_hash_fast_from_hex_str(l_hash_str, &l_datum_hash) &&
                dap_chain_hash_fast_from_base58_str(l_hash_str, &l_datum_hash)) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't convert '-hash' parameter to numeric value");
            return -111;
        }
        bool l_applied = false;
        dap_chain_datum_decree_t *l_decree = dap_chain_net_decree_get_by_hash(l_net, &l_datum_hash, &l_applied);
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified decree is %s in decrees hash-table",
                                          l_decree ? (l_applied ? "applied" : "not applied") : "not found");
    } break;
    case CMD_INFO: {
        dap_string_t *l_str_owner_pkey = dap_string_new("");
        dap_chain_net_decree_t *l_net_decree = dap_chain_net_get_net_decree(l_net);
        int i = 1;
        for (dap_list_t *l_current_pkey = l_net_decree->pkeys; l_current_pkey; l_current_pkey = l_current_pkey->next){
            dap_pkey_t *l_pkey = (dap_pkey_t*)(l_current_pkey->data);
            dap_hash_fast_t l_pkey_hash = {0};
            dap_pkey_get_hash(l_pkey, &l_pkey_hash);
            char *l_pkey_hash_str = dap_hash_fast_to_str_new(&l_pkey_hash);
            dap_string_append_printf(l_str_owner_pkey, "\t%d) %s\n", i, l_pkey_hash_str);
            i++;
            DAP_DELETE(l_pkey_hash_str);
        }
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Decree info:\n"
                                                       "\tOwners: %d\n"
                                                       "\t=====================================================================\n"
                                                       "%s"
                                                       "\t=====================================================================\n"
                                                       "\tMin owners for apply decree: %d\n",
                                          l_net_decree->num_of_owners, l_str_owner_pkey->str,
                                          l_net_decree->min_num_of_owners);
        dap_string_free(l_str_owner_pkey, true);
    } break;
    default:
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Not found decree action. Use create, sign, anchor or find parameter");
        return -1;
    }

    return 0;
}

bool s_dap_chain_node_cli_find_subcmd (char ** cmd_param, int cmd_cnt, const char * a_str)
{
    for (int i = 0; i < cmd_cnt; i++)
    {
        if (!strcmp(cmd_param[i], a_str))
        {
            return true;            
        }
    }
    return false;
}

int  json_print_for_mempool_list(dap_json_rpc_response_t* response, char ** cmd_param, int cmd_cnt){
	if (!response || !response->result_json_object) {
		printf("Response is empty\n");
		return -1;
	}
	// Raw JSON flag
	bool table_mode = false;
	for (int i = 0; i < cmd_cnt; i++) {
		const char *p = cmd_param[i];
		if (!p) continue;
		if (!strcmp(p, "-h")) {
			// show table below
			table_mode = true;
			break;
		}
	}
	if (!table_mode) { json_print_object(response->result_json_object, 0); return 0; }
	if (!s_dap_chain_node_cli_find_subcmd(cmd_param, cmd_cnt, "list"))
		return -2;

	json_object *json_obj_response = json_object_array_get_idx(response->result_json_object, 0);
	if (!json_obj_response)
		return -3;

	json_object *j_obj_net_name = NULL, *j_arr_chains = NULL;
	json_object_object_get_ex(json_obj_response, "net", &j_obj_net_name);
	json_object_object_get_ex(json_obj_response, "chains", &j_arr_chains);
	if (!j_arr_chains || json_object_get_type(j_arr_chains) != json_type_array)
		return -4;

	int chains_count = json_object_array_length(j_arr_chains);
	for (int i = 0; i < chains_count; i++) {
		json_object *json_obj_chain = json_object_array_get_idx(j_arr_chains, i);
		if (!json_obj_chain)
			continue;

		json_object *j_obj_chain_name = NULL, *j_obj_removed = NULL, *j_arr_datums = NULL, *j_obj_total = NULL;
		json_object_object_get_ex(json_obj_chain, "name", &j_obj_chain_name);
		json_object_object_get_ex(json_obj_chain, "removed", &j_obj_removed);
		json_object_object_get_ex(json_obj_chain, "datums", &j_arr_datums);
		json_object_object_get_ex(json_obj_chain, "total", &j_obj_total);

		if (j_obj_removed && j_obj_chain_name && j_obj_net_name) {
			printf("Removed %d records from the %s chain mempool in %s network.\n",
					json_object_get_int(j_obj_removed),
					json_object_get_string(j_obj_chain_name),
					json_object_get_string(j_obj_net_name));
		}

		printf("________________________________________________________________________________________________________________"
            "__________\n");
		printf("  Hash \t\t\t\t\t\t\t\t     | Datum type \t| Time create \t\t\t  |\n");

		if (j_arr_datums && json_object_get_type(j_arr_datums) == json_type_array) {
			int datums_count = json_object_array_length(j_arr_datums);
			for (int j = 0; j < datums_count; j++) {
				json_object *j_obj_datum = json_object_array_get_idx(j_arr_datums, j);
				if (!j_obj_datum)
					continue;

				json_object *j_hash = NULL, *j_type = NULL, *j_created = NULL;
				/* hash (v1: "hash", v2: "datum_hash") */
				if (!json_object_object_get_ex(j_obj_datum, "hash", &j_hash))
					json_object_object_get_ex(j_obj_datum, "datum_hash", &j_hash);
				/* type (v1: "type", v2: "datum_type") */
				if (!json_object_object_get_ex(j_obj_datum, "type", &j_type))
					json_object_object_get_ex(j_obj_datum, "datum_type", &j_type);
				/* created object { str, time_stamp } */
				json_object_object_get_ex(j_obj_datum, "created", &j_created);

				const char *hash_str = j_hash ? json_object_get_string(j_hash) : "N/A";
				const char *type_str = j_type ? json_object_get_string(j_type) : "N/A";
				const char *created_str = "N/A";
				char ts_buf[64];
				if (j_created && json_object_get_type(j_created) == json_type_object) {
					json_object *j_created_str = NULL, *j_created_ts = NULL;
					if (json_object_object_get_ex(j_created, "str", &j_created_str) && j_created_str) {
						created_str = json_object_get_string(j_created_str);
					} else if (json_object_object_get_ex(j_created, "time_stamp", &j_created_ts) && j_created_ts) {
						/* print numeric timestamp if readable string is absent */
						snprintf(ts_buf, sizeof(ts_buf), "%"DAP_INT64_FORMAT, json_object_get_int64(j_created_ts));
						created_str = ts_buf;
					}
				}

				printf("  %s | %-16s | %-24s |\n", hash_str, type_str, created_str);
			}
		} else {
			printf("  No datums\n");
		}

		printf("_____________________________________________________________________"
            "|__________________|_________________________________|\n\n");

		if (j_obj_total)
			printf("  total: %s\n", json_object_get_string(j_obj_total));
	}

	return 0;
}
int json_print_for_srv_stake_list_keys(dap_json_rpc_response_t* response, char ** cmd_param, int cmd_cnt){
    if (!response || !response->result_json_object) {
        printf("Response is empty\n");
        return -1;
    }
    // Raw JSON flag
    bool table_mode = false; 
    for (int i = 0; i < cmd_cnt; i++) { 
        const char *p = cmd_param[i]; 
        if (!p) continue; 
        if (!strcmp(p, "-h")) { 
            table_mode = true; 
            break; 
        } 
    }
    if (!table_mode) { json_print_object(response->result_json_object, 0); return 0; }
    if (!s_dap_chain_node_cli_find_subcmd(cmd_param, cmd_cnt, "list")||!s_dap_chain_node_cli_find_subcmd(cmd_param, cmd_cnt, "keys"))
        return -2;
    if (json_object_get_type(response->result_json_object) == json_type_array) {
        int result_count = json_object_array_length(response->result_json_object);
        if (result_count <= 0) {
            printf("Response array is empty\n");
            return -3;
        }
        if (table_mode) {
            printf("_________________________________________________________________________________________________________________"
                   "_________________________________________________________________________________________________________________\n");
            printf(" Node addres \t\t\t\t\t\t\t\t\t\t| Pkey hash \t\t\t\t\t\t\t\t\t\t\t\t| Stake val | Eff val | Rel weight | Sover addr \t\t\t\t\t\t\t\t\t\t\t\t   | Sover tax  |\n");
        } else {
            printf("__________________________________________________________________________________________________"
                   "_______________________________________________________________________\n");
            printf(" Node addres \t\t| Pkey hash \t\t\t\t\t\t\t\t\t\t| Stake val | Eff val | Rel weight | Sover addr \t   | Sover tax  |\n");
        }
        struct json_object *json_obj_array = json_object_array_get_idx(response->result_json_object, 0);
        result_count = json_object_array_length(json_obj_array);
        struct json_object * json_obj_total = NULL;
        for (int i = 0; i < result_count; i++) {
            struct json_object *json_obj_result = json_object_array_get_idx(json_obj_array, i);
            if (!json_obj_result) {
                printf("Failed to get array element at index %d\n", i);
                continue;
            }

            json_object *j_obj_node_addr, *j_obj_pkey_hash, *j_obj_stake_value, *j_obj_effective_value, *j_obj_related_weight,
                   *j_obj_sovereign_addr, *j_obj_sovereign_tax;
            if (json_object_object_get_ex(json_obj_result, "node_addr", &j_obj_node_addr) &&
                json_object_object_get_ex(json_obj_result, "pkey_hash", &j_obj_pkey_hash) &&
                json_object_object_get_ex(json_obj_result, "stake_value", &j_obj_stake_value) &&
                json_object_object_get_ex(json_obj_result, "effective_value", &j_obj_effective_value) &&
                json_object_object_get_ex(json_obj_result, "related_weight", &j_obj_related_weight))
            {
                json_object_object_get_ex(json_obj_result, "sovereign_addr", &j_obj_sovereign_addr);
                json_object_object_get_ex(json_obj_result, "sovereign_tax", &j_obj_sovereign_tax);

                if (j_obj_node_addr && j_obj_pkey_hash && j_obj_stake_value && j_obj_effective_value && j_obj_related_weight
                    && j_obj_sovereign_addr && j_obj_sovereign_tax) {
                    const char *node_addr_full = json_object_get_string(j_obj_node_addr);
                    const char *pkey_hash_full = json_object_get_string(j_obj_pkey_hash);
                    const char *sover_addr_full = json_object_get_string(j_obj_sovereign_addr);
                    const char *sovereign_addr_str = (sover_addr_full && strcmp(sover_addr_full, "null")) ?
                                                     (table_mode ? sover_addr_full : sover_addr_full + 85) : "-------------------";
                    printf("%s \t| %s\t|    %4d   |   %4d  |   %4d     |%s    |   %s \t|",
                            node_addr_full, pkey_hash_full,
                            json_object_get_int(j_obj_stake_value),
                            json_object_get_int(j_obj_effective_value),
                            json_object_get_int(j_obj_related_weight), 
                            sovereign_addr_str,
                            json_object_get_string(j_obj_sovereign_tax));
                } else {
                    printf("Missing required fields in array element at index %d\n", i);
                }
            } else {
                json_obj_total = json_obj_result;
                continue;
                //json_print_object(json_obj_result, 0);
            }
            printf("\n");
        }        
        if (!table_mode) {
            printf("________________________|_______________________________________________________________________|__"
                   "_________|_________|____________|_______________________|____________|\n\n");
        }
        if (json_obj_total)
            json_print_object(json_obj_total, 0);
    } else {
        json_print_object(response->result_json_object, 0);
    }
    return 0;
}

int json_print_for_srv_stake_list_tx(dap_json_rpc_response_t* response, char ** cmd_param, int cmd_cnt){
    if (!response || !response->result_json_object) {
        printf("Response is empty\n");
        return -1;
    }
    // Raw JSON flag
    bool table_mode = false; 
    for (int i = 0; i < cmd_cnt; i++) { 
        const char *p = cmd_param[i]; 
        if (!p) continue; 
        if (!strcmp(p, "-h")) { 
            table_mode = true; 
            break; 
        } 
    }
    if (!table_mode) { return 0; }
    if (!s_dap_chain_node_cli_find_subcmd(cmd_param, cmd_cnt, "list")||!s_dap_chain_node_cli_find_subcmd(cmd_param, cmd_cnt, "tx"))
        return -2;
    if (json_object_get_type(response->result_json_object) == json_type_array) {
        int result_count = json_object_array_length(response->result_json_object);
        if (result_count <= 0) {
            printf("Response array is empty\n");
            return -3;
        }
        if (table_mode) {
            printf("_________________________________________________________________________________________________________________"
                "_________________________________________________________________________________________________________________"
                "_________________________________________________________________________________________________________________\n");
            printf(" TX Hash \t\t\t\t\t\t\t    | Date \t\t\t      | Signing Addr\t\t\t\t\t\t\t\t\t\t\t\t | Signing Hash \t\t\t\t\t\t      | Node Address \t       | Value Coins | Owner Addr \t\t\t\t\t\t\t\t\t\t\t\t|\n");
        } else {
            printf("_________________________________________________________________________________________________________________"
                "________________________________________\n");
            printf(" TX Hash \t | Date \t\t\t   | Signing Addr\t | Signing Hash    | Node Address \t    | Value Coins | Owner Addr \t\t|\n");
        }
        struct json_object *json_obj_array = json_object_array_get_idx(response->result_json_object, 0);
        result_count = json_object_array_length(json_obj_array);
        struct json_object * json_obj_total = NULL;
        char hash_buffer[16];
        for (int i = 0; i < result_count; i++) {
            struct json_object *json_obj_result = json_object_array_get_idx(json_obj_array, i);
            if (!json_obj_result) {
                printf("Failed to get array element at index %d\n", i);
                continue;
            }

            json_object *j_obj_tx_hash, *j_obj_date, *j_obj_signing_addr, *j_obj_signing_hash,
                       *j_obj_node_address, *j_obj_value_coins, *j_obj_owner_addr;
            if (json_object_object_get_ex(json_obj_result, "tx_hash", &j_obj_tx_hash) &&
                json_object_object_get_ex(json_obj_result, "date", &j_obj_date) &&
                json_object_object_get_ex(json_obj_result, "signing_addr", &j_obj_signing_addr) &&
                json_object_object_get_ex(json_obj_result, "signing_hash", &j_obj_signing_hash) &&
                json_object_object_get_ex(json_obj_result, "node_address", &j_obj_node_address) &&
                json_object_object_get_ex(json_obj_result, "value_coins", &j_obj_value_coins) &&
                json_object_object_get_ex(json_obj_result, "owner_addr", &j_obj_owner_addr))
            {
                if (j_obj_tx_hash && j_obj_date && j_obj_signing_addr && j_obj_signing_hash && 
                    j_obj_node_address && j_obj_value_coins && j_obj_owner_addr) {
                    
                    // Hash display (full or shortened)
                    const char *full_tx_hash = json_object_get_string(j_obj_tx_hash);
                    const char *tx_hash_short = full_tx_hash;
                    if (!table_mode && full_tx_hash && strlen(full_tx_hash) > 15) {
                        strncpy(hash_buffer, full_tx_hash + strlen(full_tx_hash) - 15, 15);
                        hash_buffer[15] = '\0';
                        tx_hash_short = hash_buffer;
                    }
                    
                    // Signing hash display (full or shortened)
                    const char *full_signing_hash = json_object_get_string(j_obj_signing_hash);
                    char signing_hash_buffer[16];
                    const char *signing_hash_short = full_signing_hash;
                    if (!table_mode && full_signing_hash && strlen(full_signing_hash) > 15) {
                        strncpy(signing_hash_buffer, full_signing_hash + strlen(full_signing_hash) - 15, 15);
                        signing_hash_buffer[15] = '\0';
                        signing_hash_short = signing_hash_buffer;
                    }
                    
                    // Address display (full or shortened)
                    const char *signing_addr_full = j_obj_signing_addr ? json_object_get_string(j_obj_signing_addr) : NULL;
                    const char *owner_addr_full = j_obj_owner_addr ? json_object_get_string(j_obj_owner_addr) : NULL;
                    const char *node_addr_full = json_object_get_string(j_obj_node_address);
                    const char *signing_addr_str = (signing_addr_full && strcmp(signing_addr_full, "null")) ?
                                                    (table_mode ? signing_addr_full : signing_addr_full + 85) : "-------------------";
                    const char *node_addr_str = node_addr_full + 14;
                    const char *owner_addr_str = (owner_addr_full && strcmp(owner_addr_full, "null")) ?
                                                  (table_mode ? owner_addr_full : owner_addr_full + 85) : "-------------------";
                    
                    printf(" %-15s | %-13s | %-17s | %-14s | %-17s | %-11s | %-17s |\n",
                            tx_hash_short,
                            json_object_get_string(j_obj_date),
                            signing_addr_str,
                            signing_hash_short,
                            node_addr_str,
                            json_object_get_string(j_obj_value_coins),
                            owner_addr_str);
                } else {
                    printf("Missing required fields in array element at index %d\n", i);
                }
            } else {
                json_obj_total = json_obj_result;
                continue;
            }
        } 
        if (!table_mode) {
            printf("_________________|_________________________________|_____________________|_________________|" 
                      "________________________|_____________|_____________________|\n\n");
        }
        if (json_obj_total)
            json_print_object(json_obj_total, 0);
    } else {
        json_print_object(response->result_json_object, 0);
    }
    return 0;
}

/**
 * @brief json_print_for_ledger_list
 * Pretty-printer for 'ledger list' responses.
 * Handles 'coins' subcommand with flexible JSON formats:
 *  - Array of token objects (optionally followed by {limit}/{offset})
 *  - Object mapping ticker to token object
 * Uses json_object_object_foreach where keys themselves carry semantics (e.g., ticker).
 *
 * @param response JSON RPC response object
 * @param cmd_param CLI command parameters
 * @param cmd_cnt CLI parameters count
 * @return int 0 on success, negative on error
 */
int json_print_for_ledger_list(dap_json_rpc_response_t* response, char ** cmd_param, int cmd_cnt){
    if (!response || !response->result_json_object)
        return -1;
    if (!s_dap_chain_node_cli_find_subcmd(cmd_param, cmd_cnt, "list"))
        return -2;
    // Raw JSON output flag: --json or -json or json
    for (int i = 0; i < cmd_cnt; i++) {
        const char *p = cmd_param[i];
        if (!p) continue;
        if (!strcmp(p, "--json") || !strcmp(p, "-json") || !strcmp(p, "json")) {
            json_print_object(response->result_json_object, 0);
            return 0;
        }
    }

    // coins
    if (s_dap_chain_node_cli_find_subcmd(cmd_param, cmd_cnt, "coins")) {
        if (json_object_get_type(response->result_json_object) != json_type_array)
            return -3;

        json_object *root0 = json_object_array_get_idx(response->result_json_object, 0);
        if (!root0)
            return -4;

        // There are two common formats observed:
        // 1) Array of token objects [{...token fields...}, {limit:...}, {offset:...}]
        // 2) Object mapping tickers to token objects { TICKER: {...}, ... }
        // We will detect and handle both. Field names may vary between versions.

        // Case 1: array of objects where each token is an object with field token_name or subtype/supply, etc.
        if (json_object_is_type(root0, json_type_array)) {
            int arr_len = json_object_array_length(root0);
            if (arr_len <= 0) { printf("No coins found\n"); return 0; }

            printf("__________________________________________________________________________________________________________\n");
            printf("  Token Ticker   |   Type  | Decimals | Total Supply                        | Current Supply\n");
            printf("__________________________________________________________________________________________________________\n");

            int printed = 0;
            for (int i = 0; i < arr_len; i++) {
                json_object *it = json_object_array_get_idx(root0, i);
                if (!it || json_object_get_type(it) != json_type_object)
                    continue;

                // Skip control objects like {limit:...} or {offset:...}
                json_object *limit = NULL, *offset = NULL;
                if (json_object_object_get_ex(it, "limit", &limit) || json_object_object_get_ex(it, "offset", &offset))
                    continue;

                const char *ticker = NULL;
                const char *type_str = "N/A";
                const char *supply_total = "N/A";
                const char *supply_current = "N/A";
                int decimals = 0;

                json_object *j_ticker = NULL, *j_type = NULL, *j_dec = NULL, *j_supply_total = NULL, *j_supply_current = NULL;
                // keys vary by version
                if (json_object_object_get_ex(it, "token_name", &j_ticker) ||
                    json_object_object_get_ex(it, "-->Token name", &j_ticker))
                    ticker = json_object_get_string(j_ticker);
                if (json_object_object_get_ex(it, "subtype", &j_type) ||
                    json_object_object_get_ex(it, "type", &j_type))
                    type_str = json_object_get_string(j_type);
                if (json_object_object_get_ex(it, "decimals", &j_dec) ||
                    json_object_object_get_ex(it, "Decimals", &j_dec))
                    decimals = json_object_get_int(j_dec);
                if (json_object_object_get_ex(it, "supply_total", &j_supply_total) ||
                    json_object_object_get_ex(it, "Supply total", &j_supply_total))
                    supply_total = json_object_get_string(j_supply_total);
                if (json_object_object_get_ex(it, "supply_current", &j_supply_current) ||
                    json_object_object_get_ex(it, "Supply current", &j_supply_current))
                    supply_current = json_object_get_string(j_supply_current);

                if (!ticker) {
                    // try to infer ticker from first key if structure is {TICKER:{...}}
                    const char *inferred = NULL;
                    json_object_object_foreach(it, key, val) {
                        if (json_object_is_type(val, json_type_object)) { inferred = key; break; }
                    }
                    ticker = inferred ? inferred : "UNKNOWN";
                }

                printf("  %-15s|  %-7s|    %-6d|  %-35s|  %-35s|\n",
                       ticker, type_str, decimals, supply_total, supply_current);
                printed++;
            }
            if (!printed)
                printf("No coins found\n");
            return 0;
        }

        // Case 2: object mapping ticker -> token object
        if (json_object_is_type(root0, json_type_object)) {
            printf("__________________________________________________________________________________________________________\n");
            printf("  Token Ticker   |   Type  | Decimals | Total Supply                        | Current Supply\n");
            printf("__________________________________________________________________________________________________________\n");

            int printed = 0;
            json_object_object_foreach(root0, ticker, token_obj) {
                if (!token_obj || json_object_get_type(token_obj) != json_type_object)
                    continue;
                const char *type_str = "N/A";
                const char *supply_total = "N/A";
                const char *supply_current = "N/A";
                int decimals = 0;

                json_object *j_type = NULL, *j_dec = NULL, *j_supply_total = NULL, *j_supply_current = NULL;
                if (json_object_object_get_ex(token_obj, "subtype", &j_type) ||
                    json_object_object_get_ex(token_obj, "type", &j_type))
                    type_str = json_object_get_string(j_type);
                if (json_object_object_get_ex(token_obj, "decimals", &j_dec) ||
                    json_object_object_get_ex(token_obj, "Decimals", &j_dec))
                    decimals = json_object_get_int(j_dec);
                if (json_object_object_get_ex(token_obj, "supply_total", &j_supply_total) ||
                    json_object_object_get_ex(token_obj, "Supply total", &j_supply_total))
                    supply_total = json_object_get_string(j_supply_total);
                if (json_object_object_get_ex(token_obj, "supply_current", &j_supply_current) ||
                    json_object_object_get_ex(token_obj, "Supply current", &j_supply_current))
                    supply_current = json_object_get_string(j_supply_current);

                printf("  %-15s|  %-7s|    %-6d|  %-35s|  %-35s|\n",
                       ticker, type_str, decimals, supply_total, supply_current);
                printed++;
            }
            if (!printed)
                printf("No coins found\n");
            return 0;
        }

        // Fallback
        json_print_object(response->result_json_object, 0);
        return 0;
    }

    // other ledger list subcmds handled elsewhere or printed raw
    json_print_object(response->result_json_object, 0);
    return 0;
}

int json_print_for_srv_stake_list(dap_json_rpc_response_t* response, char ** cmd_param, int cmd_cnt){
    if (!response || !response->result_json_object) {
        printf("Response is empty\n");
        return -1;
    }
    // Full output flag
    bool l_full = false;
    for (int i = 0; i < cmd_cnt; i++) {
        const char *p = cmd_param[i];
        if (!p) continue;
        if (!strcmp(p, "-full") || !strcmp(p, "--full") || !strcmp(p, "full")) {
            l_full = true; break;
        }
    }
    if (!s_dap_chain_node_cli_find_subcmd(cmd_param, cmd_cnt, "order")||!s_dap_chain_node_cli_find_subcmd(cmd_param, cmd_cnt, "list"))
        return -2;
    if (json_object_get_type(response->result_json_object) == json_type_array) {
        int result_count = json_object_array_length(response->result_json_object);
        if (result_count <= 0) {
            printf("Response array is empty\n");
            return -3;
        }
        if (l_full) {
            printf("_________________________________________________________________________________________________________________"
                "__________________________________________________________________________________\n");
            printf(" Order \t\t\t\t\t\t\t\t    | Direction     | Created \t\t\t      | Price Coins \t     | Price Token | Price Unit | Node Addr \t\t | Pkey \t\t\t\t\t\t\t      |\n");
        } else {
            printf("______________________________________________________________________________"
                "__________________________________________________________________________________\n");
            printf(" Order \t\t | Direction     | Created \t\t\t   | Price Coins \t  | Price Token | Price Unit | Node Addr \t      | Pkey \t\t|\n");
        }
        struct json_object *json_obj_array = json_object_array_get_idx(response->result_json_object, 0);
        result_count = json_object_array_length(json_obj_array);
        struct json_object * json_obj_total = NULL;
        char hash_buffer[16];
        for (int i = 0; i < result_count; i++) {
            struct json_object *json_obj_result = json_object_array_get_idx(json_obj_array, i);
            if (!json_obj_result) {
                printf("Failed to get array element at index %d\n", i);
                continue;
            }

            json_object *j_obj_order, *j_obj_direction, *j_obj_created, *j_obj_price_coins,
                       *j_obj_price_token, *j_obj_price_unit, *j_obj_node_addr, *j_obj_pkey;
            if (json_object_object_get_ex(json_obj_result, "order", &j_obj_order) &&
                json_object_object_get_ex(json_obj_result, "direction", &j_obj_direction) &&
                json_object_object_get_ex(json_obj_result, "created", &j_obj_created) &&
                json_object_object_get_ex(json_obj_result, "price coins", &j_obj_price_coins) &&
                json_object_object_get_ex(json_obj_result, "price token", &j_obj_price_token) &&
                json_object_object_get_ex(json_obj_result, "price unit", &j_obj_price_unit) &&
                json_object_object_get_ex(json_obj_result, "node_addr", &j_obj_node_addr) &&
                json_object_object_get_ex(json_obj_result, "pkey", &j_obj_pkey))
            {
                if (j_obj_order && j_obj_direction && j_obj_created && j_obj_price_coins && 
                    j_obj_price_token && j_obj_price_unit && j_obj_node_addr && j_obj_pkey) {
                    
                    // Order hash display (full or shortened)
                    const char *full_order = json_object_get_string(j_obj_order);
                    const char *order_short = full_order;
                    if (!l_full && full_order && strlen(full_order) > 15) {
                        strncpy(hash_buffer, full_order + strlen(full_order) - 15, 15);
                        hash_buffer[15] = '\0';
                        order_short = hash_buffer;
                    }
                    
                    // pkey display (full or shortened)
                    const char *full_pkey = json_object_get_string(j_obj_pkey);
                    char pkey_buffer[16];
                    const char *pkey_short = full_pkey;
                    if (!l_full && full_pkey && strlen(full_pkey) > 15) {
                        strncpy(pkey_buffer, full_pkey + strlen(full_pkey) - 15, 15);
                        pkey_buffer[15] = '\0';
                        pkey_short = pkey_buffer;
                    }
                    
                    // Shortened node address display (starting from position 85, like in xchange)
                    const char *node_addr_str = json_object_get_string(j_obj_node_addr);
                    
                    printf(" %-15s | %-13s | %-17s | %-20s | %-11s | %-10s | %-13s | %-15s |\n",
                            order_short,
                            json_object_get_string(j_obj_direction),
                            json_object_get_string(j_obj_created),
                            json_object_get_string(j_obj_price_coins),
                            json_object_get_string(j_obj_price_token),
                            json_object_get_string(j_obj_price_unit),
                            node_addr_str,
                            pkey_short);
                } else {
                    printf("Missing required fields in array element at index %d\n", i);
                }
            } else {
                json_obj_total = json_obj_result;
                continue;
            }
        }        
        printf("_________________|_______________|_________________________________|______________________|"
            "_____________|____________|________________________|_________________|\n\n");
        if (json_obj_total)
            json_print_object(json_obj_total, 0);
    } else {
        json_print_object(response->result_json_object, 0);
    }
    return 0;
}

int json_print_for_srv_stake_all(dap_json_rpc_response_t* response, char ** cmd_param, int cmd_cnt){
    // Raw JSON flag
    bool table_mode_all = false; 
    for (int i = 0; i < cmd_cnt; i++) { 
        const char *p = cmd_param[i]; 
        if (!p) continue; 
        if (!strcmp(p, "-h")) { 
            table_mode_all = true; break; 
        } 
    }
    if (!table_mode_all) { return 0; }
    // Check for different srv_stake subcommands
    if (s_dap_chain_node_cli_find_subcmd(cmd_param, cmd_cnt, "list")) {
        if (s_dap_chain_node_cli_find_subcmd(cmd_param, cmd_cnt, "keys")) {
            return json_print_for_srv_stake_list_keys(response, cmd_param, cmd_cnt);
        } else if (s_dap_chain_node_cli_find_subcmd(cmd_param, cmd_cnt, "tx")) {
            return json_print_for_srv_stake_list_tx(response, cmd_param, cmd_cnt);
        } else if (s_dap_chain_node_cli_find_subcmd(cmd_param, cmd_cnt, "order")) {
            return json_print_for_srv_stake_list(response, cmd_param, cmd_cnt);
        }
    }
    
    // If no specific handler found, use default output
    if (response && response->result_json_object) {
        json_print_object(response->result_json_object, 0);
        return 0;
    }
    
    printf("Unknown srv_stake subcommand or response is empty\n");
    return -1;
}

int json_print_for_block_list(dap_json_rpc_response_t* response, char ** cmd_param, int cmd_cnt){
    int res = -1;
    // Raw JSON flag
    for (int i = 0; i < cmd_cnt; i++) {
        const char *p = cmd_param[i];
        if (!p) continue;
        if (!strcmp(p, "-h")) { /* table mode */
            // fallthrough to table printing below
            break;
        }
        if (i == cmd_cnt - 1) { // no -h seen -> default raw JSON
            if (response && response->result_json_object) {
                json_print_object(response->result_json_object, 0);
                return 0;
            }
            return -1;
        }
    }
    if (!response || !response->result_json_object) {
        printf("Response is empty\n");
        return -1;
    }
    if (!s_dap_chain_node_cli_find_subcmd(cmd_param, cmd_cnt, "list"))
        return -2;
    if (json_object_get_type(response->result_json_object) == json_type_array) {
        int result_count = json_object_array_length(response->result_json_object);
        if (result_count <= 0) {
            printf("Response array is empty\n");
            return -3;
        }
        printf("_________________________________________________________________________________________________________________\n");
        printf("  Block # | Block hash \t\t\t\t\t\t\t       | Time create \t\t\t | \n");
        struct json_object *json_obj_array = json_object_array_get_idx(response->result_json_object, 0);
        result_count = json_object_array_length(json_obj_array);
        char *l_limit = NULL;
        char *l_offset = NULL;
        for (int i = 0; i < result_count; i++) {
            struct json_object *json_obj_result = json_object_array_get_idx(json_obj_array, i);
            if (!json_obj_result) {
                printf("Failed to get array element at index %d\n", i);
                continue;
            }

            json_object *j_obj_block_number, *j_obj_hash, *j_obj_create, *j_obj_lim, *j_obj_off;
            if (json_object_object_get_ex(json_obj_result, "block number", &j_obj_block_number) &&
                json_object_object_get_ex(json_obj_result, "hash", &j_obj_hash) &&
                json_object_object_get_ex(json_obj_result, "ts_create", &j_obj_create))
            {
                if (j_obj_block_number && j_obj_hash && j_obj_create) {
                    printf("   %5s  | %s | %s |",
                            json_object_get_string(j_obj_block_number), json_object_get_string(j_obj_hash), json_object_get_string(j_obj_create));
                } else {
                    printf("Missing required fields in array element at index %d\n", i);
                }
            } else if (json_object_object_get_ex(json_obj_result, "limit", &j_obj_lim)) {
                json_object_object_get_ex(json_obj_result, "offset", &j_obj_off);
                l_limit = json_object_get_int64(j_obj_lim) ? dap_strdup_printf("%"DAP_INT64_FORMAT,json_object_get_int64(j_obj_lim)) : dap_strdup_printf("unlimit");
                if (j_obj_off)
                    l_offset = dap_strdup_printf("%"DAP_INT64_FORMAT,json_object_get_int64(j_obj_off));
                continue;
            } else {
                json_print_object(json_obj_result, 0);
            }
            printf("\n");
        }
        printf("__________|____________________________________________________________________|_________________________________|\n\n");
        if (l_limit) {            
            printf("\tlimit: %s \n", l_limit);
            DAP_DELETE(l_limit);
        }
        if (l_offset) {            
            printf("\toffset: %s \n", l_offset);
            DAP_DELETE(l_offset);
        }
    } else {
        //json_print_object(response->result_json_object, 0);
        return -4;
    }
    return 0;
}

int json_print_for_dag_list(dap_json_rpc_response_t* response, char ** cmd_param, int cmd_cnt){
    if (!response || !response->result_json_object) {
        printf("Response is empty\n");
        return -1;
    }
    // Raw JSON flag
    for (int i = 0; i < cmd_cnt; i++) {
        const char *p = cmd_param[i];
        if (!p) continue;
        if (!strcmp(p, "-h")) { /* table mode */
            break;
        }
        if (i == cmd_cnt - 1) { json_print_object(response->result_json_object, 0); return 0; }
    }
    if (!s_dap_chain_node_cli_find_subcmd(cmd_param, cmd_cnt, "list"))
        return -2;
    if (json_object_get_type(response->result_json_object) == json_type_array) {
        int result_count = json_object_array_length(response->result_json_object);
        if (result_count <= 0) {
            printf("Response array is empty\n");
            return -3;
        }
        printf("________________________________________________________________________________________________________________\n");
        printf("   # \t| Hash \t\t\t\t\t\t\t\t     | Time create \t\t\t|\n");
        struct json_object *json_obj_array = json_object_array_get_idx(response->result_json_object, 0);
        struct json_object *j_object_events = NULL;
        char *l_limit = NULL;
        char *l_offset = NULL;
        
        if (json_object_object_get_ex(json_obj_array, "events", &j_object_events) || json_object_object_get_ex(json_obj_array, "EVENTS", &j_object_events)
           || json_object_object_get_ex(json_obj_array, "TRESHOLD", &j_object_events) || json_object_object_get_ex(json_obj_array, "treshold", &j_object_events))
        {
            result_count = json_object_array_length(j_object_events);
            for (int i = 0; i < result_count; i++) {
                struct json_object *json_obj_result = json_object_array_get_idx(j_object_events, i);
                if (!json_obj_result) {
                    printf("Failed to get array element at index %d\n", i);
                    continue;
                }

                json_object *j_obj_event_number, *j_obj_hash, *j_obj_create, *j_obj_lim, *j_obj_off;
                if (json_object_object_get_ex(json_obj_result, "event number", &j_obj_event_number) &&
                    json_object_object_get_ex(json_obj_result, "hash", &j_obj_hash) &&
                    json_object_object_get_ex(json_obj_result, "ts_create", &j_obj_create))
                {
                    if (j_obj_event_number && j_obj_hash && j_obj_create) {
                        printf("   %s \t| %s | %s\t|",
                                json_object_get_string(j_obj_event_number), json_object_get_string(j_obj_hash), json_object_get_string(j_obj_create));
                    } else {
                        printf("Missing required fields in array element at index %d\n", i);
                    }
                } else if (json_object_object_get_ex(json_obj_result, "limit", &j_obj_lim)) {
                    json_object_object_get_ex(json_obj_result, "offset", &j_obj_off);
                    l_limit = json_object_get_int64(j_obj_lim) ? dap_strdup_printf("%"DAP_INT64_FORMAT,json_object_get_int64(j_obj_lim)) : dap_strdup_printf("unlimit");
                    if (j_obj_off)
                        l_offset = dap_strdup_printf("%"DAP_INT64_FORMAT,json_object_get_int64(j_obj_off));
                    continue;
                } else {
                    json_print_object(json_obj_result, 0);
                }             
                printf("\n");
            }
            printf("________|____________________________________________________________________|__________________________________|\n\n");
        } else {
            printf("EVENTS is empty\n");
            return -4;
        }
        if (l_limit) {            
            printf("\tlimit: %s \n", l_limit);
            DAP_DELETE(l_limit);
        } 
        if (l_offset) {            
            printf("\toffset: %s \n", l_offset);
            DAP_DELETE(l_offset);
        }           
    } else {
        //json_print_object(response->result_json_object, 0);
        return -5;
    }
    return 0;

}

int json_print_for_token_list(dap_json_rpc_response_t* response, char ** cmd_param, int cmd_cnt){
    if (!response || !response->result_json_object) {
        printf("Response is empty\n");
        return -1;
    }
    // Raw JSON flag
    bool table_mode_tok = false; 
    for (int i = 0; i < cmd_cnt; i++) { 
        const char *p = cmd_param[i]; 
        if (!p) continue; 
        if (!strcmp(p, "-h")) { 
            table_mode_tok = true; 
            break; 
        } 
    }
    if (!table_mode_tok) { json_print_object(response->result_json_object, 0); return 0; }
    // Raw JSON flag
    for (int i = 0; i < cmd_cnt; i++) {
        const char *p = cmd_param[i];
        if (!p) continue;
        if (!strcmp(p, "--json") || !strcmp(p, "-json") || !strcmp(p, "json")) {
            json_print_object(response->result_json_object, 0);
            return 0;
        }
    }
    if (!s_dap_chain_node_cli_find_subcmd(cmd_param, cmd_cnt, "list"))
        return -2;
    
    if (json_object_get_type(response->result_json_object) == json_type_array) {        
        int result_count = json_object_array_length(response->result_json_object);
        if (result_count <= 0) {
            printf("Response array is empty\n");
            return -3;
        }
                
        struct json_object *json_obj_main = json_object_array_get_idx(response->result_json_object, 0);
        struct json_object *j_object_tokens = NULL;
        
        // Get TOKENS or tokens array
        if (!json_object_object_get_ex(json_obj_main, "TOKENS", &j_object_tokens) &&
            !json_object_object_get_ex(json_obj_main, "tokens", &j_object_tokens)) {
            printf("TOKENS field not found\n");
            return -4;
        }
        
        int chains_count = json_object_array_length(j_object_tokens);
        if (chains_count <= 0) {
            printf("No tokens found\n");
            return -5;
        }
        
        // Print table header
        if (table_mode_tok) {
            printf("__________________________________________________________________________________________________________________________________________________________________________________"
                   "______________________________________________________________________________________________\n");
            printf("  Token Ticker   |   Type  | Decimals | Current Signs | Declarations  | Updates  | Decl Status| Decl Hash (full)                                         | Total Supply                             | Current Supply \n");
            printf("__________________________________________________________________________________________________________________________________________________________________________________"
                   "______________________________________________________________________________________________\n");
        } else {
            printf("__________________________________________________________________________________________________________________________________________________________________________________\n");
            printf("  Token Ticker   |   Type  | Decimals | Current Signs | Declarations  | Updates  | Decl Status| Decl Hash  | Total Supply                             | Current Supply \n");
            printf("__________________________________________________________________________________________________________________________________________________________________________\n");
        }
        
        int total_tokens = 0;
        
        // Iterate through chains
        for (int chain_idx = 0; chain_idx < chains_count; chain_idx++) {
            struct json_object *chain_tokens = json_object_array_get_idx(j_object_tokens, chain_idx);
            if (!chain_tokens)
                continue;
                
            // Iterate through tokens in this chain
            json_object_object_foreach(chain_tokens, ticker, token_obj) {
                total_tokens++;
                
                struct json_object *current_state = NULL;
                struct json_object *declarations = NULL;
                struct json_object *updates = NULL;
                
                json_object_object_get_ex(token_obj, "current_state", &current_state);
                json_object_object_get_ex(token_obj, "current state", &current_state);
                json_object_object_get_ex(token_obj, "declarations", &declarations);
                json_object_object_get_ex(token_obj, "updates", &updates);
                
                // Extract token info from current_state
                const char *total_supply = "N/A";
                const char *current_supply = "N/A";
                const char *token_type = "N/A";
                const char *current_signs = "N/A";                
                const char *decl_status = "N/A";
                const char *decl_hash_short = "N/A";
                int decimals = 0;
                char hash_buffer[12] = {0};
                
                if (current_state) {
                    struct json_object *total_supply_obj = NULL;
                    struct json_object *current_supply_obj = NULL;
                    struct json_object *type_obj = NULL;
                    struct json_object *signs_obj = NULL;
                    struct json_object *decimals_obj = NULL;
                    
                    if (json_object_object_get_ex(current_state, "Supply total", &total_supply_obj))
                        total_supply = json_object_get_string(total_supply_obj);
                    if (json_object_object_get_ex(current_state, "Supply current", &current_supply_obj))
                        current_supply = json_object_get_string(current_supply_obj);
                    if (json_object_object_get_ex(current_state, "type", &type_obj))
                        token_type = json_object_get_string(type_obj);
                    if (json_object_object_get_ex(current_state, "Auth signs valid", &signs_obj))
                        current_signs = json_object_get_string(signs_obj);
                    if (json_object_object_get_ex(current_state, "Decimals", &decimals_obj))
                        decimals = json_object_get_int(decimals_obj);
                }
                
                // Extract declaration info (get latest declaration)
                if (declarations && json_object_array_length(declarations) > 0) {
                    struct json_object *latest_decl = json_object_array_get_idx(declarations, 
                        json_object_array_length(declarations) - 1);
                    if (latest_decl) {
                        struct json_object *status_obj = NULL;
                        struct json_object *hash_obj = NULL;
                        
                        if (json_object_object_get_ex(latest_decl, "status", &status_obj))
                            decl_status = json_object_get_string(status_obj);
                        
                        struct json_object *datum_obj = NULL;
                        if (json_object_object_get_ex(latest_decl, "Datum", &datum_obj)) {
                            if (json_object_object_get_ex(datum_obj, "hash", &hash_obj)) {
                                const char *full_hash = json_object_get_string(hash_obj);
                                decl_hash_short = full_hash;
                                if (!table_mode_tok && full_hash && strlen(full_hash) > 10) {
                                    strncpy(hash_buffer, full_hash + strlen(full_hash) - 10, 10);
                                    hash_buffer[10] = '\0';
                                    decl_hash_short = hash_buffer;
                                } else if (full_hash) {
                                    decl_hash_short = full_hash;
                                }
                            }
                        }
                    }
                }
                
                int decl_count = declarations ? json_object_array_length(declarations) : 0;
                int upd_count = updates ? json_object_array_length(updates) : 0;
                
                printf("  %-15s|  %-7s|    %-6d|     %-10s|      %-9d|   %-7d|   %-9s|  %-10s|  %-40s|  %-40s|\n",
                    ticker,
                    token_type,
                    decimals,
                    current_signs,
                    decl_count,
                    upd_count,
                    decl_status,
                    decl_hash_short,
                    total_supply,
                    current_supply
                );
            }
        }
        
        printf("__________________________________________________________________________________________________________________________________________________________________________\n");
        printf("Total tokens: %d\n", total_tokens);
        
        // Show tokens_count if available
        struct json_object *tokens_count_obj = NULL;
        if (json_object_object_get_ex(json_obj_main, "tokens_count", &tokens_count_obj)) {
            printf("Tokens count: %s\n", json_object_get_string(tokens_count_obj));
        }
        
    } else {
        json_print_object(response->result_json_object, 0);
        return -6;
    }
    return 0;
}


int json_print_for_srv_xchange_list(dap_json_rpc_response_t* response, char ** cmd_param, int cmd_cnt){
    if (!response || !response->result_json_object) {
        printf("Response is empty\n");
        return -1;
    }
    // Raw JSON flag
    bool table_mode_sx = false; 
    for (int i = 0; i < cmd_cnt; i++) { 
        const char *p = cmd_param[i]; 
        if (!p) continue; 
        if (!strcmp(p, "-h")) { 
            table_mode_sx = true; 
            break; 
        } 
    }
    if (!table_mode_sx) { return 0; }
    struct json_object *j_obj_headr = NULL, *limit_obj = NULL, *l_arr_pagina = NULL, *l_obj_pagina = NULL,
			*offset_obj = NULL, *l_arr_orders = NULL;
	char *l_limit = NULL;
	char *l_offset = NULL;
	size_t l_print_count = 0;

	// Common header for pagination (mainly for 'orders')
	j_obj_headr = json_object_array_get_idx(response->result_json_object, 0);
	if (j_obj_headr) {
		if (json_object_object_get_ex(j_obj_headr, "pagina", &l_arr_pagina) && l_arr_pagina) {
			l_obj_pagina = json_object_array_get_idx(l_arr_pagina, 0);
			if (l_obj_pagina) {
				json_object_object_get_ex(l_obj_pagina, "limit", &limit_obj);
				json_object_object_get_ex(l_obj_pagina, "offset", &offset_obj);
				if (limit_obj)
					l_limit = json_object_get_int64(limit_obj) ? dap_strdup_printf("%"DAP_INT64_FORMAT,json_object_get_int64(limit_obj)) : dap_strdup_printf("unlimit");
				if (offset_obj)
					l_offset = json_object_get_int64(offset_obj) ? dap_strdup_printf("%"DAP_INT64_FORMAT,json_object_get_int64(offset_obj)) : NULL;
			}
		}
		if(!json_object_object_get_ex(j_obj_headr, "orders", &l_arr_orders) &&
			!json_object_object_get_ex(j_obj_headr, "ORDERS", &l_arr_orders)) {
			return -2;
		}
	}

	// Branch: orders
	if (s_dap_chain_node_cli_find_subcmd(cmd_param, cmd_cnt, "orders")) {
		if (json_object_get_type(response->result_json_object) == json_type_array && l_arr_orders) {
			int result_count = json_object_array_length(l_arr_orders);
			if (result_count <= 0) {
				printf("Response array is empty\n");
				return -3;
			}
            if (table_mode_sx) {
			    printf("______________________________________________________________________________________________"
			    	"_________________________________________________________________________________________________"
			    	"_________________________\n");
			    printf("   %-67s | %-31s | %s | %-20s | %-20s | %3s | %-10s | %-10s | %-20s |\n",
			    		"Order hash", "Time create", "Status",
			    		"Proposed coins","Amount coins","%",
			    		"Token buy", "Token sell","Rate");
            } else {
                printf("______________________________________________________________________________________________"
			    	"_______________________________________________________________________\n");
			    printf("   %-16s | %-31s | %s | %-20s | %-20s | %3s | %-10s | %-10s | %-20s |\n",
			    		"Order hash", "Time create", "Status",
			    		"Proposed coins","Amount coins","%",
			    		"Token buy", "Token sell","Rate");
            }
			for (int i = 0; i < result_count; i++) {
				struct json_object *json_obj_result = json_object_array_get_idx(l_arr_orders, i);
				json_object *j_obj_status = NULL, *j_obj_hash = NULL, *j_obj_create = NULL, *j_obj_prop_coin = NULL,
					*j_obj_amount_coin = NULL, *j_obj_filed_perc = NULL, *j_obj_token_buy = NULL, *j_obj_token_sell = NULL, *j_obj_rate = NULL;
				if (json_object_object_get_ex(json_obj_result, "order_hash", &j_obj_hash) &&
					json_object_object_get_ex(json_obj_result, "ts_created", &j_obj_create) &&
					json_object_object_get_ex(json_obj_result, "status", &j_obj_status) &&
					json_object_object_get_ex(json_obj_result, "proposed_coins", &j_obj_prop_coin) &&
					json_object_object_get_ex(json_obj_result, "amount_coins", &j_obj_amount_coin) &&
					json_object_object_get_ex(json_obj_result, "filled_percent", &j_obj_filed_perc) &&
					json_object_object_get_ex(json_obj_result, "token_buy", &j_obj_token_buy) &&
					json_object_object_get_ex(json_obj_result, "token_sell", &j_obj_token_sell) &&
					json_object_object_get_ex(json_obj_result, "rate", &j_obj_rate)) {
					const char *full_hash = json_object_get_string(j_obj_hash);
					char hash_buffer[16];
					const char *hash_print = full_hash;
					if (!table_mode_sx && full_hash && strlen(full_hash) > 15) {
						strncpy(hash_buffer, full_hash + strlen(full_hash) - 15, 15);
						hash_buffer[15] = '\0';
						hash_print = hash_buffer;
					}
					printf("   %s  | %s | %s | %-20s | %-20s | %3d | %-10s | %-10s | %-20s |\n",
						hash_print, json_object_get_string(j_obj_create), json_object_get_string(j_obj_status),
						json_object_get_string(j_obj_prop_coin), json_object_get_string(j_obj_amount_coin), (int)json_object_get_uint64(j_obj_filed_perc),
						json_object_get_string(j_obj_token_buy), json_object_get_string(j_obj_token_sell), json_object_get_string(j_obj_rate));
					l_print_count++;
				}
			}

			if (l_limit) { printf("\tlimit: %s \n", l_limit); DAP_DELETE(l_limit); }
			if (l_offset) { printf("\toffset: %s \n", l_offset); DAP_DELETE(l_offset); }
			printf("\torders printed: %zd\n", l_print_count);
		} else {
			return -4;
		}
		return 0;
	}

	// Branch: token_pair
	if (s_dap_chain_node_cli_find_subcmd(cmd_param, cmd_cnt, "token_pair")) {
		// list all
		if (s_dap_chain_node_cli_find_subcmd(cmd_param, cmd_cnt, "list")) {
			struct json_object *l_obj_pairs = NULL, *l_pairs_arr = NULL, *l_pair_cnt = NULL;
			int top_len = json_object_array_length(response->result_json_object);
			for (int i = 0; i < top_len; i++) {
				struct json_object *el = json_object_array_get_idx(response->result_json_object, i);
				if (el && json_object_get_type(el) == json_type_object) {
					if (json_object_object_get_ex(el, "tickers_pair", &l_pairs_arr) ||
						json_object_object_get_ex(el, "TICKERS PAIR", &l_pairs_arr)) { l_obj_pairs = el; break; }
				}
			}
			if (!l_obj_pairs || !l_pairs_arr || json_object_get_type(l_pairs_arr) != json_type_array) return -5;
			printf("______________________________\n");
			printf(" %-10s | %-10s |\n", "Ticker 1", "Ticker 2");
            for (size_t i = 0; i < (size_t)json_object_array_length(l_pairs_arr); i++) {
				struct json_object *pair = json_object_array_get_idx(l_pairs_arr, i);
				struct json_object *t1 = NULL, *t2 = NULL;
				json_object_object_get_ex(pair, "ticker_1", &t1);
				json_object_object_get_ex(pair, "ticker_2", &t2);
				if (t1 && t2) printf(" %-10s | %-10s |\n", json_object_get_string(t1), json_object_get_string(t2));
			}
            if (json_object_object_get_ex(l_obj_pairs, "pair_count", &l_pair_cnt) || json_object_object_get_ex(l_obj_pairs, "pair count", &l_pair_cnt))
                printf("\nTotal pairs: %"DAP_INT64_FORMAT"\n", json_object_get_int64(l_pair_cnt));
			return 0;
		}
		// rate average
		if (s_dap_chain_node_cli_find_subcmd(cmd_param, cmd_cnt, "average")) {
			int top_len = json_object_array_length(response->result_json_object);
			for (int i = 0; i < top_len; i++) {
				struct json_object *el = json_object_array_get_idx(response->result_json_object, i);
				if (el && json_object_get_type(el) == json_type_object) {
					struct json_object *avg = NULL, *last = NULL, *last_ts = NULL;
					if (json_object_object_get_ex(el, "average_rate", &avg) || json_object_object_get_ex(el, "Average rate", &avg)) {
						json_object_object_get_ex(el, "last_rate", &last); json_object_object_get_ex(el, "Last rate", &last);
						json_object_object_get_ex(el, "last_rate_time", &last_ts); json_object_object_get_ex(el, "Last rate time", &last_ts);
						printf("Average rate: %s\n", json_object_get_string(avg));
						if (last) printf("Last rate: %s\n", json_object_get_string(last));
						if (last_ts) printf("Last rate time: %s\n", json_object_get_string(last_ts));
						return 0;
					}
				}
			}
			return -6;
		}
		// rate history
		if (s_dap_chain_node_cli_find_subcmd(cmd_param, cmd_cnt, "history")) {
			struct json_object *l_arr = NULL;
			struct json_object *l_summary = NULL;
			int top_len = json_object_array_length(response->result_json_object);
			for (int i = 0; i < top_len; i++) {
				struct json_object *el = json_object_array_get_idx(response->result_json_object, i);
				if (el && json_object_get_type(el) == json_type_array && !l_arr) l_arr = el;
				if (el && json_object_get_type(el) == json_type_object) l_summary = el;
			}
			if (!l_arr) return -7;
			printf("__________________________________________________________________________________________________\n");
			printf(" Hash | Action | Token | Time create\n");
			printf("__________________________________________________________________________________________________\n");
            for (size_t i = 0; i < (size_t)json_object_array_length(l_arr); i++) {
				struct json_object *it = json_object_array_get_idx(l_arr, i);
				struct json_object *hash = NULL, *action = NULL, *token = NULL, *ts = NULL;
				json_object_object_get_ex(it, "hash", &hash);
				json_object_object_get_ex(it, "action", &action);
				json_object_object_get_ex(it, "token ticker", &token);
				json_object_object_get_ex(it, "tx created", &ts);
				if (hash && action && token && ts)
					printf(" %s | %s | %s | %s\n", json_object_get_string(hash), json_object_get_string(action), json_object_get_string(token), json_object_get_string(ts));
				else
					json_print_object(it, 1);
			}
			if (l_summary) {
				struct json_object *tx_cnt = NULL;
				struct json_object *v1_from = NULL, *v1_to = NULL, *v2_from = NULL, *v2_to = NULL;
				json_object_object_get_ex(l_summary, "tx_count", &tx_cnt);
                if (tx_cnt) printf("\nTotal transactions: %"DAP_INT64_FORMAT"\n", json_object_get_int64(tx_cnt));
				if (json_object_object_get_ex(l_summary, "trading_val_from_coins", &v1_from) || json_object_object_get_ex(l_summary, "trading_val_from_datoshi", &v2_from) ||
					json_object_object_get_ex(l_summary, "trading_val_to_coins", &v1_to) || json_object_object_get_ex(l_summary, "trading_val_to_datoshi", &v2_to)) {
					printf("Trading from: %s (%s)\n", v1_from ? json_object_get_string(v1_from) : "-", v2_from ? json_object_get_string(v2_from) : "-");
					printf("Trading to:   %s (%s)\n", v1_to ? json_object_get_string(v1_to) : "-", v2_to ? json_object_get_string(v2_to) : "-");
				}
			}
			return 0;
		}
		return -8;
	}

	// Branch: tx_list
	if (s_dap_chain_node_cli_find_subcmd(cmd_param, cmd_cnt, "tx_list")) {
		struct json_object *l_arr = NULL, *l_total = NULL;
		int top_len = json_object_array_length(response->result_json_object);
		for (int i = 0; i < top_len; i++) {
			struct json_object *el = json_object_array_get_idx(response->result_json_object, i);
			if (!el) continue;
			if (!l_arr && json_object_get_type(el) == json_type_array) l_arr = el;
			else if (json_object_get_type(el) == json_type_object) l_total = el;
		}
		if (!l_arr) return -9;
        char hash_buffer[16];
		printf("__________________________________________________________________________________________________\n");
		printf(" Hash \t\t | Status    | Token      | Time create \t\t    | Owner \t      | Buyer\n");
        for (size_t i = 0; i < (size_t)json_object_array_length(l_arr); i++) {
			struct json_object *it = json_object_array_get_idx(l_arr, i);
			struct json_object *hash = NULL, *status = NULL, *token = NULL, *ts = NULL, *owner_addr = NULL, *buyer_addr = NULL;
			json_object_object_get_ex(it, "hash", &hash);
			json_object_object_get_ex(it, "status", &status);
			json_object_object_get_ex(it, "ticker", &token);
			json_object_object_get_ex(it, "ts_created", &ts);
			json_object_object_get_ex(it, "owner_addr", &owner_addr);
			json_object_object_get_ex(it, "buyer_addr", &buyer_addr);
			const char * owner_addr_full = owner_addr ? json_object_get_string(owner_addr) : NULL;
			const char * buyer_addr_full = buyer_addr ? json_object_get_string(buyer_addr) : NULL;
			char owner_short[32] = {0}, buyer_short[32] = {0};
			const char * owner_addr_str = "-------------------";
			const char * buyer_addr_str = "-------------------";
			if (owner_addr_full && strcmp(owner_addr_full, "null")) {
				if (!table_mode_sx && strlen(owner_addr_full) > 15) {
					strncpy(owner_short, owner_addr_full + strlen(owner_addr_full) - 15, 15);
					owner_short[15] = '\0';
					owner_addr_str = owner_short;
				} else {
					owner_addr_str = owner_addr_full;
				}
			}
			if (buyer_addr_full && strcmp(buyer_addr_full, "null")) {
				if (!table_mode_sx && strlen(buyer_addr_full) > 15) {
					strncpy(buyer_short, buyer_addr_full + strlen(buyer_addr_full) - 15, 15);
					buyer_short[15] = '\0';
					buyer_addr_str = buyer_short;
				} else {
					buyer_addr_str = buyer_addr_full;
				}
			}
			if (hash && token && ts && status) {
				const char *full_hash = json_object_get_string(hash);
				char hash_buffer2[16];
				const char *hash_print = full_hash;
				if (!table_mode_sx && full_hash && strlen(full_hash) > 15) {
					strncpy(hash_buffer2, full_hash + strlen(full_hash) - 15, 15);
					hash_buffer2[15] = '\0';
					hash_print = hash_buffer2;
				}
				printf(" %-15s | %-9s | %-10s | %s | %s | %s\n", hash_print, json_object_get_string(status), json_object_get_string(token), json_object_get_string(ts), owner_addr_str, buyer_addr_str);
			} else {
				json_print_object(it, 1);
			}
		}
		if (l_total) {
			struct json_object *cnt = NULL;
			json_object_object_get_ex(l_total, "total_tx_count", &cnt);
			if (!cnt) json_object_object_get_ex(l_total, "number of transactions", &cnt);
            if (cnt) printf("\nTotal transactions: %"DAP_INT64_FORMAT"\n", json_object_get_int64(cnt));
		}
		return 0;
	}

	return -10;
}

/**
 * @brief json_print_for_tx_history_all
 * JSON parser for tx_history command responses
 * Handles different types of tx_history responses:
 * - Transaction history list with summary (for -all and -addr)
 * - Single transaction (for -tx hash)
 * - Transaction count (for -count)
 * @param response JSON RPC response object
 * @param cmd_param Command parameters array
 * @param cmd_cnt Count of command parameters
 * @return int 0 on success, negative on error
 */
int json_print_for_tx_history_all(dap_json_rpc_response_t* response, char ** cmd_param, int cmd_cnt)
{
	// Raw JSON flag
	for (int i = 0; i < cmd_cnt; i++) {
		const char *p = cmd_param[i];
		if (!p) continue;
		if (!strcmp(p, "-h")) { /* table mode */ break; }
	}
	if (!response || !response->result_json_object) {
		printf("Response is empty\n");
		return -1;
	}
	if (json_object_get_type(response->result_json_object) == json_type_array) {
		int result_count = json_object_array_length(response->result_json_object);
		if (result_count <= 0) {
			printf("Response array is empty\n");
			return -2;
		}

		// Check if this is a count response (single object with count)
		if (result_count == 1) {
			json_object *first_obj = json_object_array_get_idx(response->result_json_object, 0);
			json_object *count_obj = NULL;
			
			// Check for count response (version 1 or 2)
			if (json_object_object_get_ex(first_obj, "Number of transaction", &count_obj) ||
			    json_object_object_get_ex(first_obj, "total_tx_count", &count_obj)) {
                printf("Total transactions count: %"DAP_INT64_FORMAT"\n", json_object_get_int64(count_obj));
				return 0;
			}
		}

		// Handle transaction history list (should have 2 elements: transactions array + summary)
		if (result_count >= 2) {
			json_object *tx_array = json_object_array_get_idx(response->result_json_object, 0);
			json_object *summary_obj = json_object_array_get_idx(response->result_json_object, 1);

			// Print summary information
			if (summary_obj) {
				json_object *network_obj = NULL, *chain_obj = NULL;
				json_object *tx_sum_obj = NULL, *accepted_obj = NULL, *rejected_obj = NULL;
				
				json_object_object_get_ex(summary_obj, "network", &network_obj);
				json_object_object_get_ex(summary_obj, "chain", &chain_obj);
				json_object_object_get_ex(summary_obj, "tx_sum", &tx_sum_obj);
				json_object_object_get_ex(summary_obj, "accepted_tx", &accepted_obj);
				json_object_object_get_ex(summary_obj, "rejected_tx", &rejected_obj);

				printf("\n=== Transaction History ===\n");
				if (network_obj && chain_obj) {
					printf("Network: %s, Chain: %s\n", 
						   json_object_get_string(network_obj),
						   json_object_get_string(chain_obj));
				}
				if (tx_sum_obj && accepted_obj && rejected_obj) {
					printf("Total: %d transactions (Accepted: %d, Rejected: %d)\n\n",
						   json_object_get_int(tx_sum_obj),
						   json_object_get_int(accepted_obj),
						   json_object_get_int(rejected_obj));
				}
			}

			// Print transactions table header
			printf("_________________________________________________________________________________________________________________"
                "________________________________________________\n");
			printf(" # \t| Hash \t\t\t\t\t\t\t\t     | Status   | Action \t  | Token \t     | Time create\n");
			printf("_________________________________________________________________________________________________________________"
                "________________________________________________\n");

			// Print transaction list
			if (json_object_get_type(tx_array) == json_type_array) {
                char *l_limit = NULL;
                char *l_offset = NULL;
				int tx_count = json_object_array_length(tx_array);
				for (int i = 0; i < tx_count; i++) {
					json_object *tx_obj = json_object_array_get_idx(tx_array, i);
					if (!tx_obj) continue;

					json_object *tx_num_obj = NULL, *hash_obj = NULL;
					json_object *status_obj = NULL, *action_obj = NULL;
					json_object *token_obj = NULL, *j_obj_lim = NULL, *j_obj_off = NULL;
                    json_object *j_obj_create = NULL;

					// Get transaction fields (support both version 1 and 2)
                    if ((json_object_object_get_ex(tx_obj, "tx number", &tx_num_obj) ||
					    json_object_object_get_ex(tx_obj, "tx_num", &tx_num_obj)) &&
					    json_object_object_get_ex(tx_obj, "hash", &hash_obj) &&
					    json_object_object_get_ex(tx_obj, "status", &status_obj) &&
					    json_object_object_get_ex(tx_obj, "action", &action_obj) &&
					    json_object_object_get_ex(tx_obj, "token ticker", &token_obj) &&
                        json_object_object_get_ex(tx_obj, "tx created", &j_obj_create)) {                            

					    printf("%s\t| %-60s | %s\t| %-15s |  %-16s| %s\t|\n",
						   json_object_get_string(tx_num_obj),
						   json_object_get_string(hash_obj),
						   json_object_get_string(status_obj),
						   json_object_get_string(action_obj),
						   json_object_get_string(token_obj),
                           json_object_get_string(j_obj_create));
                    } else if (json_object_object_get_ex(tx_obj, "limit", &j_obj_lim)) {
                        json_object_object_get_ex(tx_obj, "offset", &j_obj_off);
                        l_limit = json_object_get_int64(j_obj_lim) ? dap_strdup_printf("%"DAP_INT64_FORMAT,json_object_get_int64(j_obj_lim)) : dap_strdup_printf("unlimit");
                        if (j_obj_off)
                            l_offset = dap_strdup_printf("%"DAP_INT64_FORMAT,json_object_get_int64(j_obj_off));
                    } else {
                        json_print_object(tx_obj, 0);
                    }
				}
                printf("_________________________________________________________________________________________________________________"
                    "________________________________________________\n");
                if (l_limit) {
                    printf("\tlimit: %s \n", l_limit);
                    DAP_DELETE(l_limit);
                }
                if (l_offset) {
                    printf("\toffset: %s \n", l_offset);
                    DAP_DELETE(l_offset);
                }
			}
		} else {
			// Single transaction or unknown format - fallback to JSON print
			json_print_object(response->result_json_object, 0);
		}
	} else {
		// Single object response - could be a single transaction
		json_object *hash_obj = NULL;
		if (json_object_object_get_ex(response->result_json_object, "hash", &hash_obj)) {
			// This looks like a single transaction
			printf("\n=== Single Transaction ===\n");
			json_print_object(response->result_json_object, 0);
		} else {
			// Unknown format
			json_print_object(response->result_json_object, 0);
		}
	}

	return 0;
}

/**
 * @brief json_print_for_global_db
 * Simple JSON printer for global_db command responses. It tries to format
 * known subcommands (group_list, get_keys, record get/pin/unpin, read/write/delete/drop_table, flush),
 * otherwise falls back to printing the JSON object/array as is.
 *
 * @param response JSON RPC response object
 * @param cmd_param Command parameters array
 * @param cmd_cnt Count of command parameters
 * @return int 0 on success, negative on error
 */
int json_print_for_global_db(dap_json_rpc_response_t* response, char ** cmd_param, int cmd_cnt)
{
    // Raw JSON flag
    for (int i = 0; i < cmd_cnt; i++) {
        const char *p = cmd_param[i];
        if (!p) continue;
        if (!strcmp(p, "-h")) { /* table mode */ break; }
    }
    if (!response || !response->result_json_object) {
        printf("Response is empty\n");
        return -1;
    }

    // group_list: can be an array of objects { group_name: count } or an object { group_name: count }
    if (s_dap_chain_node_cli_find_subcmd(cmd_param, cmd_cnt, "group_list")) {
        if (json_object_get_type(response->result_json_object) == json_type_array) {
            int len = json_object_array_length(response->result_json_object);
            if (len <= 0) { printf("Response array is empty\n"); return -2; }
            json_object *obj = json_object_array_get_idx(response->result_json_object, 0);
            json_object *arr = NULL, *total = NULL;
            if (obj && json_object_get_type(obj) == json_type_object) {
                // Support both spaced and underscored keys from different implementations
                json_object_object_get_ex(obj, "group_list", &arr);
                if (!arr) json_object_object_get_ex(obj, "group list", &arr);
                json_object_object_get_ex(obj, "total_count", &total);
                if (!total) json_object_object_get_ex(obj, "total count", &total);

                if (arr) {
                    int64_t groups_total = 0;
                    if (total)
                        groups_total = json_object_get_int64(total);
                    else if (json_object_get_type(arr) == json_type_array)
                        groups_total = (int64_t)json_object_array_length(arr);
                    else if (json_object_get_type(arr) == json_type_object)
                        groups_total = (int64_t)json_object_object_length(arr);

                    printf("Groups (total: %" DAP_INT64_FORMAT "):\n", groups_total);

                    if (json_object_get_type(arr) == json_type_array) {
                        for (size_t i = 0; i < (size_t)json_object_array_length(arr); i++) {
                            json_object *it = json_object_array_get_idx(arr, (int)i);
                            if (it && json_object_get_type(it) == json_type_object) {
                                json_object_object_foreach(it, key, val) {
                                    printf(" - %s: %" DAP_INT64_FORMAT "\n", key, json_object_get_int64(val));
                                }
                            }
                        }
                        return 0;
                    } else if (json_object_get_type(arr) == json_type_object) {
                        json_object_object_foreach(arr, key, val) {
                            printf(" - %s: %" DAP_INT64_FORMAT "\n", key, json_object_get_int64(val));
                        }
                        return 0;
                    }
                }
            }
            // fallback
            json_print_object(response->result_json_object, 0);
            return 0;
        }
    }

    // get_keys: array with one object containing keys_list
    if (s_dap_chain_node_cli_find_subcmd(cmd_param, cmd_cnt, "get_keys")) {
        if (json_object_get_type(response->result_json_object) == json_type_array) {
            json_object *obj = json_object_array_get_idx(response->result_json_object, 0);
            json_object *group = NULL, *keys = NULL;
            if (obj && json_object_get_type(obj) == json_type_object) {
                json_object_object_get_ex(obj, "group_name", &group);
                if (!group) json_object_object_get_ex(obj, "group name", &group);
                json_object_object_get_ex(obj, "keys_list", &keys);
                if (!keys) json_object_object_get_ex(obj, "keys list", &keys);
                if (keys && json_object_get_type(keys) == json_type_array) {
                    printf("Keys in group %s:\n", group ? json_object_get_string(group) : "<unknown>");
                    for (size_t i = 0; i < (size_t)json_object_array_length(keys); i++) {
                        json_object *it = json_object_array_get_idx(keys, (int)i);
                        json_object *k = NULL, *ts = NULL, *type = NULL;
                        if (it && json_object_get_type(it) == json_type_object) {
                            json_object_object_get_ex(it, "key", &k);
                            json_object_object_get_ex(it, "time", &ts);
                            json_object_object_get_ex(it, "type", &type);
                            printf(" - %s (%s) [%s]\n",
                                   k ? json_object_get_string(k) : "<no key>",
                                   ts ? json_object_get_string(ts) : "-",
                                   type ? json_object_get_string(type) : "-");
                        }
                    }
                    return 0;
                }
            }
        }
        json_print_object(response->result_json_object, 0);
        return 0;
    }

    // record/get + read just print json
    if (s_dap_chain_node_cli_find_subcmd(cmd_param, cmd_cnt, "record") ||
        s_dap_chain_node_cli_find_subcmd(cmd_param, cmd_cnt, "read") ||
        s_dap_chain_node_cli_find_subcmd(cmd_param, cmd_cnt, "write") ||
        s_dap_chain_node_cli_find_subcmd(cmd_param, cmd_cnt, "delete") ||
        s_dap_chain_node_cli_find_subcmd(cmd_param, cmd_cnt, "drop_table") ||
        s_dap_chain_node_cli_find_subcmd(cmd_param, cmd_cnt, "flush")) {
        json_print_object(response->result_json_object, 0);
        return 0;
    }

    // Fallback
    json_print_object(response->result_json_object, 0);
    return 0;
}

