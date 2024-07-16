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

bool s_dap_chain_datum_tx_out_data(dap_chain_datum_tx_t *a_datum,
                                          dap_ledger_t *a_ledger,
                                          json_object * json_obj_out,
                                          const char *a_hash_out_type,
                                          dap_chain_hash_fast_t *a_tx_hash)
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
    json_object_object_add(json_obj_out, "Datum_tx_hash", json_object_new_string(l_tx_hash_str));
    json_object_object_add(json_obj_out, "TS_Created", json_object_new_string(l_tmp_buf));
    json_object_object_add(json_obj_out, "Token_ticker", json_object_new_string(l_ticker));
    json_object_object_add(json_obj_out, "Token_description", l_description ? json_object_new_string(l_description)
                                                                            : json_object_new_null());
    dap_chain_datum_dump_tx_json(a_datum, l_ticker, json_obj_out, a_hash_out_type, a_tx_hash, a_ledger->net->pub.id);

    dap_list_t *l_out_items = dap_chain_datum_tx_items_get(a_datum, TX_ITEM_TYPE_OUT_ALL, NULL);
    int l_out_idx = 0;
    json_object* json_arr_items = json_object_new_array();
    bool l_spent = false;
    for (dap_list_t *l_item = l_out_items; l_item; l_item = l_item->next, ++l_out_idx) {
        switch (*(dap_chain_tx_item_type_t*)l_item->data) {
        case TX_ITEM_TYPE_OUT:
        case TX_ITEM_TYPE_OUT_OLD:
        case TX_ITEM_TYPE_OUT_EXT:
        case TX_ITEM_TYPE_OUT_COND: {
            dap_hash_fast_t l_spender = { };
            if (dap_ledger_tx_hash_is_used_out_item(a_ledger, a_tx_hash, l_out_idx, &l_spender)) {
                char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE] = { '\0' };
                dap_hash_fast_to_str(&l_spender, l_hash_str, sizeof(l_hash_str));
                json_object * l_json_obj_datum = json_object_new_object();
                json_object_object_add(l_json_obj_datum, "OUT - ", json_object_new_int(l_out_idx));
                json_object_object_add(l_json_obj_datum, "is spent by tx", json_object_new_string(l_hash_str));
                json_object_array_add(json_arr_items, l_json_obj_datum);
                l_spent = true;
            }
            break;
        }
        default:
            break;
        }
    }
    dap_list_free(l_out_items);
    json_object_object_add(json_obj_out, "Spent OUTs", json_arr_items);
    json_object_object_add(json_obj_out, "all OUTs yet unspent", l_spent ? json_object_new_string("no") : json_object_new_string("yes"));
    return true;
}

json_object * dap_db_tx_history_to_json(dap_chain_hash_fast_t* a_tx_hash,
                                        dap_hash_fast_t * l_atom_hash,
                                        dap_chain_datum_tx_t * l_tx,
                                        dap_chain_t * a_chain, 
                                        const char *a_hash_out_type, 
                                        dap_chain_net_t * l_net,
                                        int l_ret_code,
                                        bool *accepted_tx,
                                        bool brief_out)
{
    const char *l_tx_token_ticker = NULL;
    const char *l_tx_token_description = NULL;
    json_object* json_obj_datum = json_object_new_object();
    if (!json_obj_datum) {
        return NULL;
    }

    dap_ledger_t *l_ledger = dap_chain_net_by_id(a_chain->net_id)->pub.ledger;
    l_tx_token_ticker = dap_ledger_tx_get_token_ticker_by_hash(l_ledger, a_tx_hash);
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
    }

    const char *l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                        ? dap_enc_base58_encode_hash_to_str_static(a_tx_hash)
                        : dap_chain_hash_fast_to_str_static(a_tx_hash);
    json_object_object_add(json_obj_datum, "hash", json_object_new_string(l_hash_str));

    json_object_object_add(json_obj_datum, "token_ticker", l_tx_token_ticker ? json_object_new_string(l_tx_token_ticker) 
                                                                             : json_object_new_null());
    json_object_object_add(json_obj_datum, "token_description", l_tx_token_description ? json_object_new_string(l_tx_token_description)
                                                                                       : json_object_new_null());

    json_object_object_add(json_obj_datum, "ret_code", json_object_new_int(l_ret_code));
    json_object_object_add(json_obj_datum, "ret_code_str", json_object_new_string(dap_ledger_check_error_str(l_ret_code)));

    dap_chain_net_srv_uid_t uid;
    char *service_name;
    dap_chain_tx_tag_action_type_t action;

    if (dap_ledger_tx_service_info(l_ledger, a_tx_hash, &uid, &service_name, &action))
    {
        json_object_object_add(json_obj_datum, "service", json_object_new_string(service_name));
        json_object_object_add(json_obj_datum, "action", json_object_new_string(dap_ledger_tx_action_str(action)));
    }
    else
    {   
        json_object_object_add(json_obj_datum, "service", json_object_new_string("UNKNOWN"));
        json_object_object_add(json_obj_datum, "action", json_object_new_string("UNKNOWN"));
    }

    char l_time_str[DAP_TIME_STR_SIZE];
    dap_time_to_str_rfc822(l_time_str, DAP_TIME_STR_SIZE, l_tx->header.ts_created); /* Convert ts to  "Sat May 17 01:17:08 2014" */
    json_object *l_obj_ts_created = json_object_new_string(l_time_str);
    json_object_object_add(json_obj_datum, "tx_created", l_obj_ts_created);
    
    if(!brief_out)
    {        
        dap_chain_datum_dump_tx_json(l_tx,NULL,json_obj_datum,a_hash_out_type,a_tx_hash,a_chain->net_id);        
    }

    return json_obj_datum;
}

json_object * dap_db_history_tx(dap_chain_hash_fast_t* a_tx_hash, 
                      dap_chain_t * a_chain, 
                      const char *a_hash_out_type,
                      dap_chain_net_t * l_net)

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
        return dap_db_tx_history_to_json(a_tx_hash, &l_atom_hash,l_tx, a_chain, a_hash_out_type, l_net, l_ret_code, &accepted_tx, false);
    } else {
        const char *l_tx_hash_str = dap_strcmp(a_hash_out_type, "hex")
                ? dap_enc_base58_encode_hash_to_str_static(a_tx_hash)
                : dap_chain_hash_fast_to_str_static(a_tx_hash);
        dap_json_rpc_error_add(-1, "TX hash %s not founds in chains", l_tx_hash_str);
        return NULL;
    }
}

static void s_tx_header_print(json_object* json_obj_datum, dap_chain_tx_hash_processed_ht_t **a_tx_data_ht,
                              dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_atom_hash,
                              const char *a_hash_out_type, dap_ledger_t *a_ledger,
                              dap_chain_hash_fast_t *a_tx_hash, int a_ret_code)
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
        const char *l_token_ticker = dap_ledger_tx_get_token_ticker_by_hash(a_ledger, a_tx_hash);
        if (!l_token_ticker)
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


    dap_chain_net_srv_uid_t uid;
    char *service_name;
    dap_chain_tx_tag_action_type_t action;
    
    if (dap_ledger_tx_service_info(a_ledger, a_tx_hash, &uid, &service_name, &action))
    {
        json_object_object_add(json_obj_datum, "service", json_object_new_string(service_name));
        json_object_object_add(json_obj_datum, "action", json_object_new_string(dap_ledger_tx_action_str(action)));
    }
    else
    {
        json_object_object_add(json_obj_datum, "service", json_object_new_string("UNKNOWN"));
        json_object_object_add(json_obj_datum, "action", json_object_new_string("UNKNOWN"));
    }

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
json_object* dap_db_history_addr(dap_chain_addr_t *a_addr, dap_chain_t *a_chain, 
                                 const char *a_hash_out_type, const char * l_addr_str, json_object *json_obj_summary,
                                 size_t a_limit, size_t a_offset, bool a_brief, const char *a_srv, dap_chain_tx_tag_action_type_t a_action)
{
    json_object* json_obj_datum = json_object_new_array();
    if (!json_obj_datum){
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        dap_json_rpc_error_add(-44, "Memory allocation error");
        return NULL;
    }

    // add address
    json_object * json_obj_addr = json_object_new_object();
    json_object_object_add(json_obj_addr, "address", json_object_new_string(l_addr_str));
    json_object_array_add(json_obj_datum, json_obj_addr);

    dap_chain_tx_hash_processed_ht_t *l_tx_data_ht = NULL;
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    if (!l_net) {
        log_it(L_WARNING, "Can't find net by specified chain %s", a_chain->name);
        dap_json_rpc_error_add(-1, "Can't find net by specified chain %s", a_chain->name);
        json_object_put(json_obj_datum);
        return NULL;
    }
    dap_ledger_t *l_ledger = l_net->pub.ledger;
    const char *l_native_ticker = l_net->pub.native_ticker;
    if (!a_chain->callback_datum_iter_create) {
        log_it(L_WARNING, "Not defined callback_datum_iter_create for chain \"%s\"", a_chain->name);
        dap_json_rpc_error_add(-1, "Not defined callback_datum_iter_create for chain \"%s\"", a_chain->name);
        json_object_put(json_obj_datum);
        return NULL;
    }

    dap_chain_addr_t  l_net_fee_addr = {};
    bool l_net_fee_used = dap_chain_net_tx_get_fee(l_net->pub.id, NULL, &l_net_fee_addr);
    bool l_is_need_correction = false;
    uint256_t l_corr_value = {}, l_unstake_value = {};    
    bool look_for_unknown_service = (a_srv && strcmp(a_srv,"unknown") == 0);

    json_object* json_obj_lim = json_object_new_object();
    size_t l_arr_start = 0;
    if (a_offset){
        l_arr_start = a_offset;
        json_object_object_add(json_obj_lim, "offset", json_object_new_int(l_arr_start));
    }        
    size_t l_arr_end = a_chain->callback_count_atom(a_chain);
    if (a_limit) {
        json_object_object_add(json_obj_lim, "limit", json_object_new_int(a_limit));        
        l_arr_end = l_arr_start + a_limit;
        size_t l_length = a_chain->callback_count_atom(a_chain);
        if (l_arr_end > l_length)
            l_arr_end = l_length;
    }
    json_object_array_add(json_obj_datum, json_obj_lim);
    size_t i_tmp = 0;
    size_t
            l_tx_ledger_accepted = 0,
            l_tx_ledger_rejected = 0;
    // load transactions
    dap_chain_datum_iter_t *l_datum_iter = a_chain->callback_datum_iter_create(a_chain);
size_t datums = 0;
    for (dap_chain_datum_t *l_datum = a_chain->callback_datum_iter_get_first(l_datum_iter);
                            l_datum;
                            l_datum = a_chain->callback_datum_iter_get_next(l_datum_iter))
    {
        datums++;
        json_object *l_corr_object = NULL;
        if (l_datum->header.type_id != DAP_CHAIN_DATUM_TX)
            // go to next datum
            continue;        
        // it's a transaction        
        bool l_is_unstake = false;
        dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t *)l_datum->data;
        dap_list_t *l_list_in_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_IN_ALL, NULL);
        if (!l_list_in_items) // a bad tx
            continue;
        // all in items should be from the same address
        
        dap_chain_addr_t *l_src_addr = NULL;
        bool l_base_tx = false, l_reward_collect = false;
        const char *l_noaddr_token = NULL;

        dap_hash_fast_t l_tx_hash = *l_datum_iter->cur_hash;
        const char *l_src_token = dap_ledger_tx_get_token_ticker_by_hash(l_ledger, &l_tx_hash);

        int l_src_subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_UNDEFINED;
        for (dap_list_t *it = l_list_in_items; it; it = it->next) {
            dap_chain_hash_fast_t *l_tx_prev_hash = NULL;
            int l_tx_prev_out_idx;
            dap_chain_datum_tx_t *l_tx_prev = NULL;
            switch (*(byte_t *)it->data) {
            case TX_ITEM_TYPE_IN: {
                dap_chain_tx_in_t *l_tx_in = (dap_chain_tx_in_t *)it->data;
                l_tx_prev_hash = &l_tx_in->header.tx_prev_hash;
                l_tx_prev_out_idx = l_tx_in->header.tx_out_prev_idx;
            } break;
            case TX_ITEM_TYPE_IN_COND: {
                dap_chain_tx_in_cond_t *l_tx_in_cond = (dap_chain_tx_in_cond_t *)it->data;
                l_tx_prev_hash = &l_tx_in_cond->header.tx_prev_hash;
                l_tx_prev_out_idx = l_tx_in_cond->header.tx_out_prev_idx;
            } break;
            case TX_ITEM_TYPE_IN_EMS: {
                dap_chain_tx_in_ems_t *l_tx_in_ems = (dap_chain_tx_in_ems_t *)it->data;
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

            dap_chain_datum_t *l_datum = l_tx_prev_hash ?
                        a_chain->callback_datum_find_by_hash(a_chain, l_tx_prev_hash, NULL, NULL) : NULL;
            l_tx_prev = l_datum && l_datum->header.type_id == DAP_CHAIN_DATUM_TX ? (dap_chain_datum_tx_t *)l_datum->data : NULL;
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
                case TX_ITEM_TYPE_OUT_COND: {
                    dap_chain_tx_out_cond_t *l_cond_prev = (dap_chain_tx_out_cond_t *)l_prev_out_union;
                    l_src_subtype = l_cond_prev->header.subtype;
                    if (l_cond_prev->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE)
                        l_noaddr_token = l_native_ticker;
                    else {
                        if (l_cond_prev->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK) {
                            l_is_unstake = true;
                            l_unstake_value = l_cond_prev->header.value;
                        }
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
        dap_list_free(l_list_in_items);

        // find OUT items
        bool l_header_printed = false;
        uint256_t l_fee_sum = uint256_0;
        dap_list_t *l_list_out_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_OUT_ALL, NULL);
        json_object * j_arr_data = json_object_new_array();
        json_object * j_obj_tx = json_object_new_object();
        if (!j_obj_tx || !j_arr_data) {
            dap_json_rpc_allocation_error;
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
                json_object_put(j_obj_tx);
                dap_list_free(l_list_out_items);
                continue;
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
            case TX_ITEM_TYPE_OUT_COND:
                l_value = ((dap_chain_tx_out_cond_t *)it->data)->header.value;
                if (((dap_chain_tx_out_cond_t *)it->data)->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE) {
                    SUM_256_256(l_fee_sum, ((dap_chain_tx_out_cond_t *)it->data)->header.value, &l_fee_sum);
                    l_dst_token = l_native_ticker;
                } else
                    l_dst_token = l_src_token;
            default:
                break;
            }

            if (l_src_addr && l_dst_addr &&
                    dap_chain_addr_compare(l_dst_addr, l_src_addr) &&
                    dap_strcmp(l_noaddr_token, l_dst_token))
                continue;   // sent to self (coinback)

            if (l_dst_addr && l_net_fee_used && dap_chain_addr_compare(&l_net_fee_addr, l_dst_addr))
                SUM_256_256(l_fee_sum, l_value, &l_fee_sum);
            
            //tag
            char *service_name = NULL;
            dap_chain_tx_tag_action_type_t l_action;
            bool srv_found = dap_ledger_tx_service_info(l_ledger, &l_tx_hash, NULL, &service_name, &l_action);
            if (!(l_action & a_action))
                continue;

            if (a_srv)
            {
              
                //skip if looking for UNKNOWN + it is known
                if (look_for_unknown_service && srv_found) {
                    continue;
                }
                            
                //skip if search condition provided, it not UNKNOWN and found name not match
                if (!look_for_unknown_service && (!srv_found || strcmp(service_name, a_srv) != 0))
                {
                    continue;
                }
            }

            if (l_dst_addr && dap_chain_addr_compare(l_dst_addr, a_addr)) {
                if (!l_header_printed) {
                    s_tx_header_print(j_obj_tx, &l_tx_data_ht, l_tx, l_datum_iter->cur_atom_hash,
                                      a_hash_out_type, l_ledger, &l_tx_hash, l_datum_iter->ret_code);
                    l_header_printed = true;
                }
                const char *l_src_str = NULL;
                if (l_base_tx)
                    l_src_str = l_reward_collect ? "reward collecting" : "emission";
                else if (l_src_addr && dap_strcmp(l_dst_token, l_noaddr_token))
                    l_src_str = dap_chain_addr_to_str(l_src_addr);
                else
                    l_src_str = dap_chain_tx_out_cond_subtype_to_str(l_src_subtype);
                if (l_is_unstake)
                    l_value = l_unstake_value;
                else if (!dap_strcmp(l_native_ticker, l_noaddr_token)) {
                    l_is_need_correction = true;
                    l_corr_value = l_value;
                }
                const char *l_coins_str, *l_value_str = dap_uint256_to_char(l_value, &l_coins_str);
                if (i_tmp >= l_arr_end || i_tmp < l_arr_start) {
                    i_tmp++;
                    continue;                    
                }
                i_tmp++;
                
                json_object *j_obj_data = json_object_new_object();
                if (!j_obj_data) {
                    dap_json_rpc_allocation_error;
                    json_object_put(j_obj_tx);
                    json_object_put(j_arr_data);
                    return NULL;
                }
                l_src_token ? l_tx_ledger_accepted++ : l_tx_ledger_rejected++;
                json_object_object_add(j_obj_data, "tx_type", json_object_new_string("recv"));
                json_object_object_add(j_obj_data, "recv_coins", json_object_new_string(l_coins_str));
                json_object_object_add(j_obj_data, "recv_datoshi", json_object_new_string(l_value_str));
                json_object_object_add(j_obj_data, "token", l_dst_token ? json_object_new_string(l_dst_token)
                                                                            : json_object_new_string("UNKNOWN"));
                json_object_object_add(j_obj_data, "source_address", json_object_new_string(l_src_str));
                if (l_is_need_correction)
                    l_corr_object = j_obj_data;
                else
                    json_object_array_add(j_arr_data, j_obj_data);
                
            } else if (!l_src_addr || dap_chain_addr_compare(l_src_addr, a_addr)) {
                if (!l_dst_addr && ((dap_chain_tx_out_cond_t *)it->data)->header.subtype == l_src_subtype && l_src_subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE)
                    continue;
                if (!l_src_addr && l_dst_addr && !dap_chain_addr_compare(l_dst_addr, &l_net_fee_addr))
                    continue;                
                if (!l_header_printed) {
                    s_tx_header_print(j_obj_tx, &l_tx_data_ht, l_tx, l_datum_iter->cur_atom_hash,
                                      a_hash_out_type, l_ledger, &l_tx_hash, l_datum_iter->ret_code);
                    l_header_printed = true;
                }

                const char *l_dst_addr_str = l_dst_addr ? dap_chain_addr_to_str(l_dst_addr)
                                                        : dap_chain_tx_out_cond_subtype_to_str(
                                                              ((dap_chain_tx_out_cond_t *)it->data)->header.subtype);
                const char *l_coins_str, *l_value_str = dap_uint256_to_char(l_value, &l_coins_str);
                if (i_tmp >= l_arr_end || i_tmp < l_arr_start) {
                    i_tmp++;
                    continue;                    
                }
                i_tmp++;
                json_object * j_obj_data = json_object_new_object();
                if (!j_obj_data) {
                    dap_json_rpc_allocation_error;
                    json_object_put(j_obj_tx);
                    json_object_put(j_arr_data);
                    return NULL;
                }
                l_src_token ? l_tx_ledger_accepted++ : l_tx_ledger_rejected++;
                json_object_object_add(j_obj_data, "tx_type", json_object_new_string("send"));
                json_object_object_add(j_obj_data, "send_coins", json_object_new_string(l_coins_str));
                json_object_object_add(j_obj_data, "send_datoshi", json_object_new_string(l_value_str));
                json_object_object_add(j_obj_data, "token", l_dst_token ? json_object_new_string(l_dst_token)
                                                                        : json_object_new_string("UNKNOWN"));
                json_object_object_add(j_obj_data, "destination_address", json_object_new_string(l_dst_addr_str));
                json_object_array_add(j_arr_data, j_obj_data);                
            }
        }
        if (json_object_array_length(j_arr_data) > 0) {
            json_object_object_add(j_obj_tx, "data", j_arr_data);
            json_object_array_add(json_obj_datum, j_obj_tx);
        } else {
            json_object_put(j_arr_data);
            json_object_put(j_obj_tx);
        }
        dap_list_free(l_list_out_items);
        if (l_is_need_correction && l_corr_object) {
            SUM_256_256(l_corr_value, l_fee_sum, &l_corr_value);
            const char *l_coins_str, *l_value_str = dap_uint256_to_char(l_corr_value, &l_coins_str);
            json_object_object_add(l_corr_object, "recv_coins", json_object_new_string(l_coins_str));
            json_object_object_add(l_corr_object, "recv_datoshi", json_object_new_string(l_value_str));
            if (!j_arr_data) {
                j_arr_data = json_object_new_array();
            }
            json_object_array_add(j_arr_data, l_corr_object);
            l_is_need_correction = false;
        }
    }
    a_chain->callback_datum_iter_delete(l_datum_iter);
    // delete hashes
    s_dap_chain_tx_hash_processed_ht_free(&l_tx_data_ht);
    
    // if no history
    if (json_object_array_length(json_obj_datum) == 1) {
        json_object * json_empty_tx = json_object_new_object();
        if (!json_empty_tx) {
            dap_json_rpc_allocation_error;
            json_object_put(json_obj_datum);
            return NULL;
        }
        json_object_object_add(json_empty_tx, "status", json_object_new_string("empty"));        
        json_object_array_add(json_obj_datum, json_empty_tx);
    }    
    json_object_object_add(json_obj_summary, "network", json_object_new_string(l_net->pub.name));
    json_object_object_add(json_obj_summary, "chain", json_object_new_string(a_chain->name));
    json_object_object_add(json_obj_summary, "tx_sum", json_object_new_int(i_tmp));
    json_object_object_add(json_obj_summary, "accepted_tx", json_object_new_int(l_tx_ledger_accepted));
    json_object_object_add(json_obj_summary, "rejected_tx", json_object_new_int(l_tx_ledger_rejected));    
    return json_obj_datum;
}

json_object *dap_db_history_tx_all(dap_chain_t *l_chain, dap_chain_net_t *l_net,
                                   const char *l_hash_out_type, json_object *json_obj_summary,
                                   size_t a_limit, size_t a_offset, bool out_brief,
					const char *a_srv, 
                                    dap_chain_tx_tag_action_type_t a_action)
{
        log_it(L_DEBUG, "Start getting tx from chain");
        size_t
            l_tx_ledger_accepted = 0,
            l_tx_ledger_rejected = 0,
            l_count = 0,
            l_count_tx = 0;
        dap_chain_cell_t    *l_cell = NULL,
                            *l_cell_tmp = NULL;
        dap_chain_atom_iter_t *l_iter = NULL;
        json_object * json_arr_out = json_object_new_array();
        json_object* json_obj_lim = json_object_new_object();
        size_t l_arr_start = 0;
        if (a_offset) {
            l_arr_start = a_offset;
            json_object_object_add(json_obj_lim, "offset", json_object_new_int(l_arr_start));            
        }
        size_t l_arr_end =  l_chain->callback_count_atom(l_chain);
        l_arr_end = a_limit ? l_arr_start + a_limit : 0;
        l_arr_end ? json_object_object_add(json_obj_lim, "limit", json_object_new_int(l_arr_end - l_arr_start)):
                    json_object_object_add(json_obj_lim, "limit", json_object_new_string("unlimit"));
        json_object_array_add(json_arr_out, json_obj_lim);
        
        
        bool look_for_unknown_service = (a_srv && strcmp(a_srv,"unknown") == 0);
        HASH_ITER(hh, l_chain->cells, l_cell, l_cell_tmp) {            
            if ((l_count_tx >= l_arr_end)&&(l_arr_end))
                break;
            l_iter = l_chain->callback_atom_iter_create(l_chain, l_cell->id, NULL);
            size_t l_atom_size = 0;
            dap_chain_atom_ptr_t l_ptr = l_chain->callback_atom_iter_get(l_iter, DAP_CHAIN_ITER_OP_FIRST, &l_atom_size);
            while (l_ptr && l_atom_size && ((l_count_tx < l_arr_end)||(!l_arr_end))) {
                size_t l_datums_count = 0;
                dap_chain_datum_t **l_datums = l_cell->chain->callback_atom_get_datums(l_ptr, l_atom_size, &l_datums_count);
                for (size_t i = 0; i < l_datums_count && ((l_count_tx < l_arr_end)||(!l_arr_end)); i++) {
                    if (l_datums[i]->header.type_id == DAP_CHAIN_DATUM_TX) {
                        if (l_count_tx < l_arr_start) {
                            l_count_tx++;
                            continue;
                        }
                        dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t*)l_datums[i]->data;
                        dap_hash_fast_t l_ttx_hash = {0};
                        dap_hash_fast(l_tx, l_datums[i]->header.data_size, &l_ttx_hash);

                        char *service_name = NULL;
                        dap_chain_tx_tag_action_type_t l_action = DAP_CHAIN_TX_TAG_ACTION_UNKNOWN;
                        
                        dap_ledger_t *l_ledger = l_net->pub.ledger;
                        bool srv_found = dap_ledger_tx_service_info(l_ledger, &l_ttx_hash, NULL, &service_name, &l_action);

                        if (!(l_action & a_action))                        
                            continue;

                        if (a_srv)
                        {
                            char *service_name = NULL;
                            bool srv_found = dap_ledger_tx_service_info(l_ledger, &l_ttx_hash, NULL, &service_name, NULL);
                            //skip if looking for UNKNOWN + it is known
                            if (look_for_unknown_service && srv_found) {
                                continue;
                            }
                            
                            //skip if search condition provided, it not UNKNOWN and found name not match
                            if (!look_for_unknown_service && (!srv_found || strcmp(service_name, a_srv) != 0))
                            {
                                continue;
                            }
                        }        
                        
                        bool accepted_tx;
                        json_object* json_obj_datum = dap_db_tx_history_to_json(&l_ttx_hash, NULL, l_tx, l_chain, l_hash_out_type, l_net, 0, &accepted_tx, out_brief);
                        if (!json_obj_datum) {
                            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                            return NULL;
                        }
                        if (accepted_tx) {
                            ++l_tx_ledger_accepted;
                        } else {
                            ++l_tx_ledger_rejected;
                        }
                        json_object_array_add(json_arr_out, json_obj_datum);
                        //const char * debug_json_string = json_object_to_json_string(json_obj_datum);
                        ++l_count_tx;
                        l_count++;
                    }
                }
                DAP_DEL_Z(l_datums);
                l_ptr = l_chain->callback_atom_iter_get(l_iter, DAP_CHAIN_ITER_OP_NEXT, &l_atom_size);
            }
            l_cell->chain->callback_atom_iter_delete(l_iter);
        }
        log_it(L_DEBUG, "END getting tx from chain");

        json_object_object_add(json_obj_summary, "network", json_object_new_string(l_net->pub.name));
        json_object_object_add(json_obj_summary, "chain", json_object_new_string(l_chain->name));
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
static json_object* dap_db_chain_history_token_list(dap_chain_t * a_chain, const char *a_token_name, const char *a_hash_out_type, size_t *a_token_num)
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
            json_object *l_current_state = dap_ledger_token_info_by_name(l_ledger, l_token->ticker);
            json_object_object_add(l_jobj_ticker, "current state", l_current_state);
            l_jobj_decls = json_object_new_array();
            l_jobj_updates = json_object_new_array();
            json_object_object_add(l_jobj_ticker, "declarations", l_jobj_decls);
            json_object_object_add(l_jobj_ticker, "updates", l_jobj_updates);
            json_object_object_add(l_jobj_tickers, l_token->ticker, l_jobj_ticker);
        } else {
            l_jobj_decls = json_object_object_get(l_jobj_ticker, "declarations");
            l_jobj_updates = json_object_object_get(l_jobj_ticker, "updates");
        }
        int l_ret_code = l_datum_iter->ret_code;
        json_object* json_history_token = json_object_new_object();
        json_object_object_add(json_history_token, "status", json_object_new_string(l_ret_code ? "DECLINED" : "ACCEPTED"));
        json_object_object_add(json_history_token, "Ledger return code", json_object_new_int(l_ret_code));
        dap_chain_datum_dump_json(json_history_token, l_datum, a_hash_out_type, a_chain->net_id);
        switch (l_token->type) {
            case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_SIMPLE:
            case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_PUBLIC:
            case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_PRIVATE_DECL:
            case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_NATIVE_DECL:
            case DAP_CHAIN_DATUM_TOKEN_TYPE_DECL:
                json_object_array_add(l_jobj_decls, json_history_token);
                break;
            case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_PRIVATE_UPDATE:
            case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_NATIVE_UPDATE:
            case DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE:
                json_object_array_add(l_jobj_updates, json_history_token);
                break;
        }
        DAP_DELETE(l_token);
        l_token_num++;
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

static size_t dap_db_net_history_token_list(dap_chain_net_t * l_net, const char *a_token_name, const char *a_hash_out_type, json_object* a_obj_out) {
    size_t l_token_num_total = 0;
    dap_chain_t *l_chain_cur;
    json_object* json_arr_obj_tx = json_object_new_array();    
    DL_FOREACH(l_net->pub.chains, l_chain_cur) {
        size_t l_token_num = 0;
        json_object* json_obj_tx = NULL;
        json_obj_tx = dap_db_chain_history_token_list(l_chain_cur, a_token_name, a_hash_out_type, &l_token_num);
        if(json_obj_tx)
            json_object_array_add(json_arr_obj_tx, json_obj_tx);
        l_token_num_total += l_token_num;        
    }
    json_object_object_add(a_obj_out, "TOKENS", json_arr_obj_tx);
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
int com_ledger(int a_argc, char ** a_argv, void **reply)
{
    json_object ** json_arr_reply = (json_object **) reply;
    enum { CMD_NONE, CMD_LIST, CMD_TX_INFO };
    int arg_index = 1;
    const char *l_net_str = NULL;
    const char *l_tx_hash_str = NULL;
    const char *l_hash_out_type = NULL;

    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR, "invalid parameter -H, valid values: -H <hex | base58>");
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
        dap_chain_hash_fast_t l_tx_threshold_hash;
        const char *l_limit_str = NULL;
        const char *l_offset_str = NULL;
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
                    dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_LEDGER_TRESHOLD_ERR, "tx threshold hash not recognized");
                    return DAP_CHAIN_NODE_CLI_COM_LEDGER_TRESHOLD_ERR;
                }
            }
        }
        if (l_sub_cmd == SUBCMD_NONE) {
            dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR, "Command 'list' requires subcommands 'coins' or 'threshold'");
            return DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR;
        }
        dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-net", &l_net_str);
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-limit", &l_limit_str);
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-offset", &l_offset_str);
        size_t l_limit = l_limit_str ? strtoul(l_limit_str, NULL, 10) : 1000;
        size_t l_offset = l_offset_str ? strtoul(l_offset_str, NULL, 10) : 0;
        if (l_net_str == NULL){
            dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_LEDGER_NET_PARAM_ERR, "Command 'list' requires key -net");
            return DAP_CHAIN_NODE_CLI_COM_LEDGER_NET_PARAM_ERR;
        }
        dap_ledger_t *l_ledger = dap_ledger_by_net_name(l_net_str);
        if (l_ledger == NULL){
            dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_LEDGER_LACK_ERR, "Can't get ledger for net %s", l_net_str);
            return DAP_CHAIN_NODE_CLI_COM_LEDGER_LACK_ERR;
        }
        if (l_sub_cmd == SUB_CMD_LIST_LEDGER_THRESHOLD){
            json_object* json_obj_out = dap_ledger_threshold_info(l_ledger, l_limit, l_offset);
            if (json_obj_out){
                json_object_array_add(*json_arr_reply, json_obj_out);
            }
            return 0;
        }
        if (l_sub_cmd == SUB_CMD_LIST_LEDGER_THRESHOLD_WITH_HASH){
            json_object *json_obj_out = dap_ledger_threshold_hash_info(l_ledger, &l_tx_threshold_hash, l_limit, l_offset);
            if (json_obj_out){
                json_object_array_add(*json_arr_reply, json_obj_out);
            }
            return 0;
        }
        if (l_sub_cmd == SUB_CMD_LIST_LEDGER_BALANCE){
            json_object *json_obj_out = dap_ledger_balance_info(l_ledger, l_limit, l_offset);
            if (json_obj_out){
                json_object_array_add(*json_arr_reply, json_obj_out);
            }
            return 0;
        }
        json_object *json_obj_datum = dap_ledger_token_info(l_ledger, l_limit, l_offset);

        if (json_obj_datum) {
            json_object_array_add(*json_arr_reply, json_obj_datum);
        }
        return 0;
    } else if (l_cmd == CMD_TX_INFO){
        //GET hash
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-hash", &l_tx_hash_str);
        //get net
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_str);
        //get search type
        bool l_unspent_flag = dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-unspent", NULL);
        //check input
        if (l_tx_hash_str == NULL){
            dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR, "Subcommand 'info' requires key -hash");
            return DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR;
        }
        if (l_net_str == NULL){
            dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_LEDGER_NET_PARAM_ERR, "Subcommand 'info' requires key -net");
            return DAP_CHAIN_NODE_CLI_COM_LEDGER_NET_PARAM_ERR;
        }
        dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
        if (!l_net) {
            dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_LEDGER_NET_FIND_ERR, "Can't find net %s", l_net_str);
            return DAP_CHAIN_NODE_CLI_COM_LEDGER_NET_FIND_ERR;
        }
        dap_chain_hash_fast_t *l_tx_hash = DAP_NEW(dap_chain_hash_fast_t);
        if (dap_chain_hash_fast_from_str(l_tx_hash_str, l_tx_hash)) {
            dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_LEDGER_HASH_GET_ERR, "Can't get hash_fast from %s, check that the hash is correct", l_tx_hash_str);
            DAP_DEL_Z(l_tx_hash);
            return DAP_CHAIN_NODE_CLI_COM_LEDGER_HASH_GET_ERR;
        }
        dap_chain_datum_tx_t *l_datum_tx = dap_chain_net_get_tx_by_hash(l_net, l_tx_hash,
                                                                        l_unspent_flag ? TX_SEARCH_TYPE_NET_UNSPENT : TX_SEARCH_TYPE_NET);
        if (l_datum_tx == NULL) {
            dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_LEDGER_TX_HASH_ERR, "Can't find datum for transaction hash %s in chains", l_tx_hash_str);
            DAP_DEL_Z(l_tx_hash);
            return DAP_CHAIN_NODE_CLI_COM_LEDGER_TX_HASH_ERR;
        }
        json_object* json_datum = json_object_new_object();
        if (!s_dap_chain_datum_tx_out_data(l_datum_tx, l_net->pub.ledger, json_datum, l_hash_out_type, l_tx_hash)){
            dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_LEDGER_TX_HASH_ERR, "Can't find transaction hash %s in ledger", l_tx_hash_str);
            json_object_put(json_datum);
            DAP_DEL_Z(l_tx_hash);
            return DAP_CHAIN_NODE_CLI_COM_LEDGER_TX_HASH_ERR;
        }
        DAP_DEL_Z(l_tx_hash);
        if (json_datum){
            json_object_array_add(*json_arr_reply, json_datum);
        }        
    }
    else{
        dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR, "Command 'ledger' requires parameter 'list' or 'info'", l_tx_hash_str);
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
int com_token(int a_argc, char ** a_argv, void **a_str_reply)
{
    json_object **json_arr_reply = (json_object **)a_str_reply;
    enum { CMD_NONE, CMD_LIST, CMD_INFO, CMD_TX };
    int arg_index = 1;
    const char *l_net_str = NULL;
    dap_chain_net_t * l_net = NULL;

    const char * l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    if (!l_hash_out_type)
        l_hash_out_type = "hex";
    if (dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_TOKEN_PARAM_ERR, "invalid parameter -H, valid values: -H <hex | base58>");
        return -DAP_CHAIN_NODE_CLI_COM_TOKEN_PARAM_ERR;
    }

    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_str);
    // Select chain network
    if(!l_net_str) {
        dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_TOKEN_PARAM_ERR, "command requires parameter '-net'");
        return -DAP_CHAIN_NODE_CLI_COM_TOKEN_PARAM_ERR;
    } else {
        if((l_net = dap_chain_net_by_name(l_net_str)) == NULL) { // Can't find such network
        dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_TOKEN_PARAM_ERR,
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
        size_t l_token_num_total = dap_db_net_history_token_list(l_net, NULL, l_hash_out_type, json_obj_tx);

        //total
        json_object_object_add(json_obj_tx, "tokens", json_object_new_uint64(l_token_num_total));
        json_object_array_add(*json_arr_reply, json_obj_tx);
        return 0;
    }
    // token info
    else if(l_cmd == CMD_INFO) {
        const char *l_token_name_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-name", &l_token_name_str);
        if(!l_token_name_str) {
            dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_TOKEN_PARAM_ERR, "command requires parameter '-name' <token name>");
            return -DAP_CHAIN_NODE_CLI_COM_TOKEN_PARAM_ERR;
        }
        json_object *json_obj_tx = json_object_new_object();
        if (!dap_db_net_history_token_list(l_net, l_token_name_str, l_hash_out_type, json_obj_tx)) {
            dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_TOKEN_FOUND_ERR, "token '%s' not found\n", l_token_name_str);\
            return -DAP_CHAIN_NODE_CLI_COM_TOKEN_UNKNOWN;
        }
        json_object_array_add(*json_arr_reply, json_obj_tx);
        return DAP_CHAIN_NODE_CLI_COM_TOKEN_OK;
    }
    // command tx history
    else if(l_cmd == CMD_TX) {
        dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_TOKEN_UNKNOWN, 
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
                    char *ffl_addr_base58 = dap_chain_addr_to_str(l_addr_base58);
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

    dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_TOKEN_UNKNOWN, "unknown command code %d", l_cmd);
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
        dap_sign_t * l_sign = dap_cert_sign(a_certs[i],  a_datum_anchor,
           sizeof(dap_chain_datum_anchor_t) + a_datum_anchor->header.data_size, 0);

        if (l_sign) {
            size_t l_sign_size = dap_sign_get_size(l_sign);
            a_datum_anchor = DAP_REALLOC(a_datum_anchor, sizeof(dap_chain_datum_anchor_t) + l_cur_sign_offset + l_sign_size);
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
int cmd_decree(int a_argc, char **a_argv, void **a_str_reply)
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
                    char l_str_to_reply_chain[500] = {0};
                    char *l_str_to_reply = NULL;
                    sprintf(l_str_to_reply_chain, "%s requires parameter '-chain' to be valid chain name in chain net %s. Current chain %s is not valid\n",
                                                    a_argv[0], l_net_str, l_chain_str);
                    l_str_to_reply = dap_strcat2(l_str_to_reply,l_str_to_reply_chain);
                    dap_chain_t * l_chain;
                    l_str_to_reply = dap_strcat2(l_str_to_reply,"\nAvailable chain with decree support:\n");
                    l_chain = dap_chain_net_get_chain_by_chain_type(l_net, CHAIN_TYPE_DECREE);
                    l_str_to_reply = dap_strcat2(l_str_to_reply,"\t");
                    l_str_to_reply = dap_strcat2(l_str_to_reply,l_chain->name);
                    l_str_to_reply = dap_strcat2(l_str_to_reply,"\n");
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_str_to_reply);
                    return -103;
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
                    char l_str_to_reply_chain[500] = {0};
                    char *l_str_to_reply = NULL;
                    sprintf(l_str_to_reply_chain, "%s requires parameter '-decree_chain' to be valid chain name in chain net %s. Current chain %s is not valid\n",
                                                    a_argv[0], l_net_str, l_chain_str);
                    l_str_to_reply = dap_strcat2(l_str_to_reply,l_str_to_reply_chain);
                    dap_chain_t * l_chain;
                    dap_chain_net_t * l_chain_net = l_net;
                    l_str_to_reply = dap_strcat2(l_str_to_reply,"\nAvailable chains:\n");
                    DL_FOREACH(l_chain_net->pub.chains, l_chain) {
                            l_str_to_reply = dap_strcat2(l_str_to_reply,"\t");
                            l_str_to_reply = dap_strcat2(l_str_to_reply,l_chain->name);
                            l_str_to_reply = dap_strcat2(l_str_to_reply,"\n");
                    }
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_str_to_reply);
                    return -103;
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
                    char l_str_to_reply_chain[500] = {0};
                    char *l_str_to_reply = NULL;
                    sprintf(l_str_to_reply_chain, "%s requires parameter '-chain' to be valid chain name in chain net %s. Current chain %s is not valid\n",
                                                    a_argv[0], l_net_str, l_chain_str);
                    l_str_to_reply = dap_strcat2(l_str_to_reply,l_str_to_reply_chain);
                    dap_chain_t * l_chain;
                    l_str_to_reply = dap_strcat2(l_str_to_reply,"\nAvailable chain with decree support:\n");
                    l_chain = dap_chain_net_get_chain_by_chain_type(l_net, CHAIN_TYPE_DECREE);
                    l_str_to_reply = dap_strcat2(l_str_to_reply,"\t");
                    l_str_to_reply = dap_strcat2(l_str_to_reply,l_chain->name);
                    l_str_to_reply = dap_strcat2(l_str_to_reply,"\n");
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_str_to_reply);
                    return -103;
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
                    dap_chain_datum_decree_t *l_datum_decree = DAP_DUP_SIZE(l_datum->data, l_datum->header.data_size);    // for realloc
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
            DAP_DELETE(l_datum_hash_hex_str);
            DAP_DELETE(l_datum_hash_base58_str);
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
                char l_str_to_reply_chain[500] = {0};
                char *l_str_to_reply = NULL;
                sprintf(l_str_to_reply_chain, "%s requires parameter '-chain' to be valid chain name in chain net %s. Current chain %s is not valid\n",
                                                a_argv[0], l_net_str, l_chain_str);
                l_str_to_reply = dap_strcat2(l_str_to_reply,l_str_to_reply_chain);
                dap_chain_t * l_chain;
                l_str_to_reply = dap_strcat2(l_str_to_reply,"\nAvailable chain with anchor support:\n");
                l_chain = dap_chain_net_get_chain_by_chain_type(l_net, CHAIN_TYPE_ANCHOR);
                l_str_to_reply = dap_strcat2(l_str_to_reply,"\t");
                l_str_to_reply = dap_strcat2(l_str_to_reply,l_chain->name);
                l_str_to_reply = dap_strcat2(l_str_to_reply,"\n");
                dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_str_to_reply);
                return -103;
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
                return -108;
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
