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
#include "dap_chain_datum_tx.h"
#include "dap_ht.h"
#include "dap_cli_server.h"
#include "dap_cli_error_codes.h"
#include "dap_chain_ledger_cli_error_codes.h"
#include "dap_chain_ledger_cli_compat.h"  // Compatibility layer for old error codes
#include "dap_common.h"
#include "dap_enc_base58.h"
#include "dap_strfuncs.h"
#include "dap_string.h"
#include "dap_list.h"
#include "dap_hash.h"
#include "dap_time.h"
#include "dap_chain_datum.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_ledger_cli.h"
#include "dap_json.h"
#include "dap_chain_ledger.h"
#include "dap_chain_ledger_cli.h"
#include "dap_chain_ledger_cli_error_codes.h"
#include "dap_chain_net_types.h"
#include "dap_cli_error_codes.h"
#include "dap_math_convert.h"
#include "dap_json_rpc_errors.h"
#include "dap_enc_base64.h"
#include "dap_chain_tx_compose_api.h"

// Functions from higher-level modules used by com_ledger.
// These are forward declarations to avoid circular #include dependencies.
// TODO: refactor com_ledger to remove these cross-module calls.
extern int dap_chain_net_tx_to_json(dap_chain_datum_tx_t *a_tx, dap_json_t *a_json);
extern char *dap_chain_mempool_datum_add(const dap_chain_datum_t *a_datum, dap_chain_t *a_chain, const char *a_hash_out_type);

#define LOG_TAG "chain_ledger_cli"

#define DAP_LEDGER_CLI_ERROR_TX_NO_WALLET_SIGN_FUNC        (-20)
#define DAP_LEDGER_CLI_ERROR_TX_NO_WALLET_CHECK_SIGN_FUNC  (-21)
#define DAP_LEDGER_CLI_ERROR_TX_NO_WALLET_GET_ADDR_FUNC    (-22)
#define DAP_LEDGER_CLI_ERROR_MEMORY_ALLOC                  (-23)

#define dap_cli_error_get_code(x) (x)
#define dap_cli_error_get_str(x)  #x

// Local helper structure for CLI output - tracks already printed transactions to avoid duplicates in single command output
typedef struct dap_chain_tx_hash_processed_ht {
    dap_hash_sha3_256_t hash;
    dap_ht_handle_t hh;
} dap_chain_tx_hash_processed_ht_t;

static bool s_dap_chain_datum_tx_out_data(dap_json_t *a_json_arr_reply,
                                   dap_chain_datum_tx_t *a_datum,
                                   dap_ledger_t *a_ledger,
                                   dap_json_t *json_obj_out,
                                   const char *a_hash_out_type,
                                   dap_hash_sha3_256_t *a_tx_hash,
                                   int a_version);

static dap_json_t *s_tx_history_to_json(dap_json_t *a_json_arr_reply,
                                  dap_hash_sha3_256_t* a_tx_hash,
                                  dap_hash_sha3_256_t * l_atom_hash,
                                  dap_chain_datum_tx_t * l_tx,
                                  dap_chain_t * a_chain,
                                  dap_ledger_t *a_ledger, 
                                  const char *a_hash_out_type, 
                                  dap_chain_datum_iter_t *a_datum_iter,
                                  int l_ret_code,
                                  bool out_brief,
                                  int a_version);


// Helper to free local TX tracking hash table (used in CLI commands)
static void s_tx_hash_processed_ht_free(dap_chain_tx_hash_processed_ht_t **a_hash_processed)
{
    if (!a_hash_processed || !*a_hash_processed)
        return;
    dap_chain_tx_hash_processed_ht_t *l_tmp, *l_current;
    dap_ht_foreach(*a_hash_processed, l_current, l_tmp) {
        dap_ht_del(*a_hash_processed, l_current);
        DAP_DELETE(l_current);
    }
}

static bool s_dap_chain_datum_tx_out_data(dap_json_t *a_json_arr_reply,
                                          dap_chain_datum_tx_t *a_datum,
                                          dap_ledger_t *a_ledger,
                                          dap_json_t *json_obj_out,
                                          const char *a_hash_out_type,
                                          dap_hash_sha3_256_t *a_tx_hash,
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
    dap_hash_sha3_256_to_str(a_tx_hash,l_tx_hash_str,sizeof(l_tx_hash_str));
    dap_json_object_add_string(json_obj_out, a_version == 1 ? "Datum_tx_hash" : "datum_tx_hash", l_tx_hash_str);
    dap_json_object_add_string(json_obj_out, a_version == 1 ? "TS_Created" : "ts_created", l_tmp_buf);
    dap_json_object_add_string(json_obj_out, a_version == 1 ? "Token_ticker" : "token_ticker", l_ticker);
    dap_json_object_add_object(json_obj_out, a_version == 1 ? "Token_description" : "token_description", l_description ? dap_json_object_new_string(l_description)
                                                                            : dap_json_object_new());
    // Use ledger's net_id directly - ledger already knows its network
    dap_chain_datum_dump_tx_json(a_json_arr_reply, a_datum, l_ticker, json_obj_out, a_hash_out_type, a_tx_hash, a_ledger->net_id, a_version);
    dap_json_t *json_arr_items = dap_json_array_new();
    bool l_spent = false;
    byte_t *l_item; size_t l_size; int i, l_out_idx = -1;
    TX_ITEM_ITER_TX_TYPE(l_item, TX_ITEM_TYPE_OUT_ALL, l_size, i, a_datum) {
        ++l_out_idx;
        dap_hash_sha3_256_t l_spender = { };
        dap_json_t *l_json_obj_out = NULL, *l_json_arr_colours = NULL;
        if ( dap_ledger_tx_hash_is_used_out_item(a_ledger, a_tx_hash, l_out_idx, &l_spender) ) {
            char l_hash_str[DAP_HASH_SHA3_256_STR_SIZE] = { '\0' };
            dap_hash_sha3_256_to_str(&l_spender, l_hash_str, sizeof(l_hash_str));
            l_json_obj_out = dap_json_object_new();
            dap_json_object_add_int(l_json_obj_out, a_version == 1 ? "OUT - " : "out", l_out_idx);
            dap_json_object_add_string(l_json_obj_out, a_version == 1 ? "is spent by tx" : "spent_by_tx", l_hash_str);
            l_spent = true;
        }
        dap_list_t *l_trackers = dap_ledger_tx_get_trackers(a_ledger, a_tx_hash, l_out_idx);
        if (l_trackers) {
            if (!l_json_obj_out) {
                l_json_obj_out = dap_json_object_new();
                dap_json_object_add_int(l_json_obj_out, "out_number", l_out_idx);
            }
            l_json_arr_colours = dap_json_array_new();
            dap_json_object_add_object(l_json_obj_out, "trackers", l_json_arr_colours);
        }
        for (dap_list_t *it = l_trackers; it; it = it->next) {
            dap_ledger_tracker_t *l_tracker = it->data;
            dap_json_t *l_json_obj_tracker = dap_json_object_new();
            dap_json_array_add(l_json_arr_colours, l_json_obj_tracker);
            const char *l_voling_hash_str = dap_hash_sha3_256_to_str_static(&l_tracker->voting_hash);
            dap_json_object_add_string(l_json_obj_tracker, "voting_hash", l_voling_hash_str);
            dap_json_t *l_json_arr_tracker_items = dap_json_array_new();
            dap_json_object_add_object(l_json_obj_tracker, "items", l_json_arr_tracker_items);
            for (dap_ledger_tracker_item_t *l_item = l_tracker->items; l_item; l_item = l_item->next) {
                dap_json_t *l_json_obj_tracker_item = dap_json_object_new();
                dap_json_array_add(l_json_arr_tracker_items, l_json_obj_tracker_item);
                const char *l_pkey_hash_str = dap_hash_sha3_256_to_str_static(&l_item->pkey_hash);
                dap_json_object_add_string(l_json_obj_tracker_item, "pkey_hash", l_pkey_hash_str);
                const char *l_coloured_coins, *l_coloured_value = dap_uint256_to_const_char(l_item->coloured_value, &l_coloured_coins);
                dap_json_object_add_string(l_json_obj_tracker_item, "coloured_coins", l_coloured_coins);
                dap_json_object_add_string(l_json_obj_tracker_item, "coloured_value", l_coloured_value);
            }
        }
        if (l_json_obj_out)
            dap_json_array_add(json_arr_items, l_json_obj_out);
    }
    dap_json_object_add_object(json_obj_out, a_version == 1 ? "Spent OUTs" : "spent_or_coloured_outs", json_arr_items);
    dap_json_object_add_object(json_obj_out, a_version == 1 ? "all OUTs yet unspent" : "all_outs_yet_unspent", l_spent ? dap_json_object_new_string("no") : dap_json_object_new_string("yes"));
    return true;
}

static dap_json_t *s_tx_history_to_json(dap_json_t *a_json_arr_reply,
                                         dap_hash_sha3_256_t* a_tx_hash,
                                         dap_hash_sha3_256_t * l_atom_hash,
                                         dap_chain_datum_tx_t * l_tx,
                                         dap_chain_t * a_chain,
                                         dap_ledger_t *a_ledger, 
                                         const char *a_hash_out_type, 
                                         dap_chain_datum_iter_t *a_datum_iter,
                                         int l_ret_code,
                                         bool brief_out,
                                         int a_version)
{
    const char *l_tx_token_description = NULL;
    dap_json_t *json_obj_datum = dap_json_object_new();
    if (!json_obj_datum) {
        return NULL;
    }

    dap_ledger_t *l_ledger = a_ledger;  // Use passed ledger directly
    const char *l_tx_token_ticker = a_datum_iter ?
                      a_datum_iter->token_ticker : dap_ledger_tx_get_token_ticker_by_hash(l_ledger, a_tx_hash);
    if (!l_ret_code) {
        dap_json_object_add_string(json_obj_datum, "status", "ACCEPTED");
        l_tx_token_description = dap_ledger_get_description_by_ticker(l_ledger, l_tx_token_ticker);
    } else {
        dap_json_object_add_string(json_obj_datum, "status", "DECLINED");
    }

    if (l_atom_hash) {
        const char *l_atom_hash_str = dap_strcmp(a_hash_out_type, "hex")
                            ? dap_enc_base58_encode_hash_to_str_static(l_atom_hash)
                            : dap_hash_sha3_256_to_str_static(l_atom_hash);
        dap_json_object_add_string(json_obj_datum, "atom_hash", l_atom_hash_str);
        dap_chain_atom_iter_t *l_iter = a_chain->callback_atom_iter_create(a_chain, c_dap_chain_cell_id_null, l_atom_hash);
        size_t l_size = 0;
        if(a_chain->callback_atom_find_by_hash(l_iter, l_atom_hash, &l_size) != NULL){
            uint64_t l_block_count = a_chain->callback_count_atom(a_chain);
            uint64_t l_confirmations = l_block_count - l_iter->cur_num;
            dap_json_object_add_uint64(json_obj_datum, "confirmations", l_confirmations);
        }
        a_chain->callback_atom_iter_delete(l_iter);
    }

    const char *l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                        ? dap_enc_base58_encode_hash_to_str_static(a_tx_hash)
                        : dap_hash_sha3_256_to_str_static(a_tx_hash);
    dap_json_object_add_string(json_obj_datum, "hash", l_hash_str);
    
    dap_json_object_add_string(json_obj_datum, "token_ticker", l_tx_token_ticker ? l_tx_token_ticker : "UNKNOWN");
    if (l_tx_token_description) 
        dap_json_object_add_string(json_obj_datum, "token_description", l_tx_token_description);

    dap_json_object_add_int(json_obj_datum, "ret_code", l_ret_code);
    dap_json_object_add_string(json_obj_datum, "ret_code_str", dap_ledger_check_error_str(l_ret_code));

    dap_chain_srv_uid_t uid;
    char *service_name;
    dap_chain_tx_tag_action_type_t action;
    bool srv_found = a_datum_iter ? a_datum_iter->uid.uint64 ? true : false
                                  : dap_ledger_tx_service_info(l_ledger, a_tx_hash, &uid, &service_name, &action);
    if (a_datum_iter)action = a_datum_iter->action;

    if (srv_found)
    {
        //dap_json_object_add_string(json_obj_datum, "service", service_name);
        dap_json_object_add_string(json_obj_datum, "action", dap_ledger_tx_action_str(action));
    }
    else
    {   
        //dap_json_object_add_string(json_obj_datum, "service", "UNKNOWN");
        dap_json_object_add_string(json_obj_datum, "action", "UNKNOWN");
    }
    dap_json_object_add_object(json_obj_datum, "batching", dap_json_object_new_string(!dap_chain_datum_tx_item_get_tsd_by_type(l_tx, DAP_CHAIN_DATUM_TRANSFER_TSD_TYPE_OUT_COUNT) ? "false" : "true"));
    if(!brief_out)
    {        
        dap_chain_datum_dump_tx_json(a_json_arr_reply, l_tx, l_tx_token_ticker ? l_tx_token_ticker : NULL,
                                     json_obj_datum, a_hash_out_type, a_tx_hash, a_chain->net_id, a_version);
    }

    return json_obj_datum;
}

dap_json_t *dap_db_history_tx(dap_json_t *a_json_arr_reply,
                      dap_hash_sha3_256_t* a_tx_hash, 
                      dap_chain_t * a_chain, 
                      const char *a_hash_out_type,
                      dap_ledger_t *a_ledger,
                      int a_version)

{
    if (!a_chain->callback_datum_find_by_hash) {
        log_it(L_WARNING, "Not defined callback_datum_find_by_hash for chain \"%s\"", a_chain->name);
        return NULL;
    }

    int l_ret_code = 0;
    dap_hash_sha3_256_t l_atom_hash = {0};
    //search tx
    dap_chain_datum_t *l_datum = a_chain->callback_datum_find_by_hash(a_chain, a_tx_hash, &l_atom_hash, &l_ret_code);
    dap_chain_datum_tx_t *l_tx = l_datum  && l_datum->header.type_id == DAP_CHAIN_DATUM_TX ?
                                 (dap_chain_datum_tx_t *)l_datum->data : NULL;

    if (l_tx) {
        return s_tx_history_to_json(a_json_arr_reply, a_tx_hash, &l_atom_hash, l_tx, a_chain, a_ledger, a_hash_out_type, NULL, l_ret_code, false, a_version);
    } else {
        const char *l_tx_hash_str = dap_strcmp(a_hash_out_type, "hex")
                ? dap_enc_base58_encode_hash_to_str_static(a_tx_hash)
                : dap_hash_sha3_256_to_str_static(a_tx_hash);
        dap_json_rpc_error_add(a_json_arr_reply, -1, "TX hash %s not founds in chains", l_tx_hash_str);
        return NULL;
    }
}

static void s_tx_header_print(dap_json_t *json_obj_datum, dap_chain_tx_hash_processed_ht_t **a_tx_data_ht,
                              dap_chain_datum_tx_t *a_tx, dap_chain_t *a_chain, const char *a_hash_out_type, 
                              dap_ledger_t *a_ledger, dap_hash_sha3_256_t *a_tx_hash, dap_hash_sha3_256_t *a_atom_hash, const char* a_token_ticker, 
                              int a_ret_code, dap_chain_tx_tag_action_type_t a_action, dap_chain_srv_uid_t a_uid)
{
    bool l_declined = false;
    // transaction time
    char l_time_str[DAP_TIME_STR_SIZE] = "unknown";                                /* Prefill string */
    if (a_tx->header.ts_created)
        dap_time_to_str_rfc822(l_time_str, DAP_TIME_STR_SIZE, a_tx->header.ts_created); /* Convert ts to  "Sat May 17 01:17:08 2014" */
    dap_chain_tx_hash_processed_ht_t *l_tx_data = NULL;
    dap_ht_find(*a_tx_data_ht, a_tx_hash, sizeof(*a_tx_hash), l_tx_data);
    if (l_tx_data)  // this tx already present in ledger (double)
        l_declined = true;
    else {
        l_tx_data = DAP_NEW_Z(dap_chain_tx_hash_processed_ht_t);
        if (!l_tx_data) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            return;
        }
        l_tx_data->hash = *a_tx_hash;
        dap_ht_add(*a_tx_data_ht, hash, l_tx_data);
        
               
        if (a_ret_code)
            l_declined = true;
    }

    char *l_tx_hash_str, *l_atom_hash_str;
    if (!dap_strcmp(a_hash_out_type, "hex")) {
        l_tx_hash_str = dap_hash_sha3_256_to_str_new(a_tx_hash);
        l_atom_hash_str = dap_hash_sha3_256_to_str_new(a_atom_hash);
    } else {
        l_tx_hash_str = dap_enc_base58_encode_hash_to_str(a_tx_hash);
        l_atom_hash_str = dap_enc_base58_encode_hash_to_str(a_atom_hash);
    }
    dap_json_object_add_string(json_obj_datum, "status", l_declined ? "DECLINED" : "ACCEPTED");
    dap_json_object_add_string(json_obj_datum, "hash", l_tx_hash_str);
    dap_json_object_add_string(json_obj_datum, "atom_hash", l_atom_hash_str);
    dap_json_object_add_int(json_obj_datum, "ret_code", a_ret_code);
    dap_json_object_add_string(json_obj_datum, "ret_code_str", dap_ledger_check_error_str(a_ret_code));


    bool srv_found = a_uid.uint64 ? true : false;
    
    if (srv_found)
    {
        dap_json_object_add_string(json_obj_datum, "action", dap_ledger_tx_action_str(a_action));
        dap_json_object_add_string(json_obj_datum, "service", dap_ledger_tx_tag_str_by_uid(a_uid));
    }
    else
    {
        dap_json_object_add_string(json_obj_datum, "action", "UNKNOWN");
        dap_json_object_add_string(json_obj_datum, "service", "UNKNOWN");
    }

    dap_json_object_add_object(json_obj_datum, "batching", dap_json_object_new_string(!dap_chain_datum_tx_item_get_tsd_by_type(a_tx, DAP_CHAIN_DATUM_TRANSFER_TSD_TYPE_OUT_COUNT) ? "false" : "true"));
    dap_json_object_add_string(json_obj_datum, "tx_created", l_time_str);

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
dap_json_t *dap_db_history_addr(dap_json_t *a_json_arr_reply, dap_chain_addr_t *a_addr, dap_chain_t *a_chain,
                                dap_ledger_t *a_ledger,
                                const char *a_hash_out_type, const char * l_addr_str, dap_json_t *json_obj_summary,
                                 size_t a_limit, size_t a_offset, bool a_brief, const char *a_srv, dap_chain_tx_tag_action_type_t a_action, bool a_head,
                                 int a_version)
{
    dap_json_t *json_obj_datum = dap_json_array_new();
    if (!json_obj_datum){
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        dap_json_rpc_error_add(a_json_arr_reply, -44, "Memory allocation error");
        return NULL;
    }

    // add address
    dap_json_t *json_obj_addr = dap_json_object_new();
    dap_json_object_add_string(json_obj_addr, a_version == 1 ? "address" : "addr", l_addr_str);
    dap_json_array_add(json_obj_datum, json_obj_addr);

    dap_chain_tx_hash_processed_ht_t *l_tx_data_ht = NULL;
    // Get ledger for this chain using chain's net_id - ledger knows its network
    dap_chain_info_t *l_chain_info = dap_ledger_get_chain_info_by_name(a_ledger, a_chain->name);
    if (!l_chain_info) {
        log_it(L_WARNING, "Chain %s not registered in ledger", a_chain->name);
        dap_json_rpc_error_add(a_json_arr_reply, -1, "Chain %s not registered in ledger", a_chain->name);
        dap_json_object_free(json_obj_datum);
        return NULL;
    }
    dap_ledger_t *l_ledger = a_ledger;  // Use passed ledger directly
    const char *l_native_ticker = l_ledger->native_ticker;  // Ledger knows native ticker
    if (!a_chain->callback_datum_iter_create) {
        log_it(L_WARNING, "Not defined callback_datum_iter_create for chain \"%s\"", a_chain->name);
        dap_json_rpc_error_add(a_json_arr_reply, -1, "Not defined callback_datum_iter_create for chain \"%s\"", a_chain->name);
        dap_json_object_free(json_obj_datum);
        return NULL;
    }

    // Use ledger's fee configuration - ledger knows network fees
    dap_chain_addr_t l_net_fee_addr = l_ledger->fee_addr;
    bool l_net_fee_used = !IS_ZERO_256(l_ledger->fee_value);  // Fee is used if non-zero
    bool look_for_unknown_service = (a_srv && strcmp(a_srv,"unknown") == 0);
    size_t l_arr_start = 0;
    size_t l_arr_end = 0;

    dap_chain_set_offset_limit_json(json_obj_datum, &l_arr_start, &l_arr_end, a_limit, a_offset, a_chain->callback_count_tx(a_chain),false);
    
    size_t i_tmp = 0;
    size_t
            l_count = 0,
            l_tx_ledger_accepted = 0,
            l_tx_ledger_rejected = 0;
   
    dap_hash_sha3_256_t l_curr_tx_hash = {};
    // Use wallet cache callback if registered, otherwise fallback to chain iteration
    bool l_from_cache = false;
    if (a_ledger->wallet_cache_tx_find_in_history_callback) {
        l_from_cache = a_ledger->wallet_cache_tx_find_in_history_callback(a_addr, NULL, NULL, NULL, NULL, NULL, &l_curr_tx_hash) == 0;
    }
    if (l_from_cache && a_addr->net_id.uint64 != a_ledger->net_id.uint64){
        log_it(L_WARNING, "Can't find wallet with addr %s in net", l_addr_str);
        dap_json_rpc_error_add(a_json_arr_reply, -1, "Can't find wallet with addr %s in net", l_addr_str);
        dap_json_object_free(json_obj_datum);
        return NULL;
    }
    memset(&l_curr_tx_hash, 0, sizeof(dap_hash_sha3_256_t));
    dap_chain_datum_tx_t *l_tx = NULL;
    

    dap_chain_datum_iter_t *l_datum_iter = NULL;
    dap_ledger_wallet_cache_iter_t *l_wallet_cache_iter = NULL;
    dap_chain_datum_callback_iters  iter_begin = NULL;
    dap_chain_datum_callback_iters  iter_direc = NULL;
    dap_ledger_wallet_cache_direction_t cache_iter_begin = DAP_LEDGER_WALLET_CACHE_GET_FIRST, 
                                        cache_iter_direc = DAP_LEDGER_WALLET_CACHE_GET_NEXT;


    if (!l_from_cache){
        l_datum_iter = a_chain->callback_datum_iter_create(a_chain);   
        iter_begin = a_head ? a_chain->callback_datum_iter_get_first
                        : a_chain->callback_datum_iter_get_last;
        iter_direc = a_head ? a_chain->callback_datum_iter_get_next
                        : a_chain->callback_datum_iter_get_prev;         
    } else{
        if (!a_ledger->wallet_cache_iter_create_callback) {
            log_it(L_WARNING, "Wallet cache callbacks not registered, falling back to chain iteration");
            l_from_cache = false;
            l_datum_iter = a_chain->callback_datum_iter_create(a_chain);   
            iter_begin = a_head ? a_chain->callback_datum_iter_get_first
                            : a_chain->callback_datum_iter_get_last;
            iter_direc = a_head ? a_chain->callback_datum_iter_get_next
                            : a_chain->callback_datum_iter_get_prev;
        } else {
            l_wallet_cache_iter = a_ledger->wallet_cache_iter_create_callback(*a_addr);
            cache_iter_begin = a_head ? DAP_LEDGER_WALLET_CACHE_GET_FIRST : DAP_LEDGER_WALLET_CACHE_GET_LAST;
            cache_iter_direc = a_head ? DAP_LEDGER_WALLET_CACHE_GET_NEXT : DAP_LEDGER_WALLET_CACHE_GET_PREVIOUS;
        }
    }

    dap_chain_datum_t *l_datum = NULL;
    dap_chain_datum_tx_t *l_cur_tx_cache = NULL;
    if (!l_from_cache)
        l_datum = iter_begin(l_datum_iter);
    else
        l_cur_tx_cache = a_ledger->wallet_cache_iter_get_callback(l_wallet_cache_iter, cache_iter_begin);

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
        dap_json_t *l_corr_object = NULL, *l_cond_recv_object = NULL, *l_cond_send_object = NULL;
        
        dap_chain_addr_t *l_src_addr = NULL;
        bool l_base_tx = false, l_reward_collect = false;
        const char *l_noaddr_token = NULL;

        // Always get data from datum iterator (wallet cache is just for filtering)
        dap_hash_sha3_256_t l_tx_hash = *l_datum_iter->cur_hash;
        const char *l_src_token = l_datum_iter->token_ticker;
        int l_ret_code = l_datum_iter->ret_code;
        uint32_t l_action = l_datum_iter->action;
        dap_hash_sha3_256_t l_atom_hash = *l_datum_iter->cur_atom_hash;
        dap_chain_srv_uid_t l_uid = l_datum_iter->uid;

        int l_src_subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_UNDEFINED;
        uint8_t *l_tx_item = NULL;
        size_t l_size; int i, q = 0;
        // Check all INs
        TX_ITEM_ITER_TX_TYPE(l_tx_item, TX_ITEM_TYPE_IN_ALL, l_size, i, l_tx) {
            dap_hash_sha3_256_t *l_tx_prev_hash = NULL;
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
        dap_json_t *j_arr_data = dap_json_array_new();
        dap_json_t *j_obj_tx = dap_json_object_new();
        if (!j_obj_tx || !j_arr_data) {
            dap_json_rpc_allocation_error(a_json_arr_reply);
            dap_json_object_free(j_obj_tx);
            dap_json_object_free(j_arr_data);
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
                dap_json_object_free(j_arr_data);
                j_arr_data = NULL;
                dap_json_object_free(j_obj_tx);
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
                    // SUM_256_256(l_fee_sum, l_value, &l_fee_sum);
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

            // if (l_dst_addr && l_net_fee_used && dap_chain_addr_compare(&l_net_fee_addr, l_dst_addr))
            //     SUM_256_256(l_fee_sum, l_value, &l_fee_sum);
            
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
                const char *l_coins_str, *l_value_str = dap_uint256_to_const_char(l_value, &l_coins_str);                 

                dap_json_t *j_obj_data = dap_json_object_new();
                if (!j_obj_data) {
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    dap_json_object_free(j_obj_tx);
                    dap_json_object_free(j_arr_data);
                    return NULL;
                }                
                dap_json_object_add_string(j_obj_data, "tx_type", "recv");
                dap_json_object_add_string(j_obj_data, "recv_coins", l_coins_str);
                dap_json_object_add_string(j_obj_data, "recv_datoshi", l_value_str);
                dap_json_object_add_object(j_obj_data, "token", l_dst_token ? dap_json_object_new_string(l_dst_token)
                                                                            : dap_json_object_new_string("UNKNOWN"));
                dap_json_object_add_string(j_obj_data, "source_address", l_src_str);
                if (l_recv_from_cond && !l_cond_recv_object)
                    l_cond_recv_object = j_obj_data;
                else
                    dap_json_array_add(j_arr_data, j_obj_data);
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
                const char *l_coins_str, *l_value_str = dap_uint256_to_const_char(l_value, &l_coins_str);
                                
                dap_json_t *j_obj_data = dap_json_object_new();
                if (!j_obj_data) {
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    dap_json_object_free(j_obj_tx);
                    dap_json_object_free(j_arr_data);
                    return NULL;
                }                
                dap_json_object_add_string(j_obj_data, "tx_type", "send");
                dap_json_object_add_string(j_obj_data, "send_coins", l_coins_str);
                dap_json_object_add_string(j_obj_data, "send_datoshi", l_value_str);
                dap_json_object_add_object(j_obj_data, "token", l_dst_token ? dap_json_object_new_string(l_dst_token)
                                                                        : dap_json_object_new_string("UNKNOWN"));
                dap_json_object_add_string(j_obj_data, "destination_address", l_dst_addr_str);
                if (l_send_to_same_cond && !l_cond_send_object)
                    l_cond_send_object = j_obj_data;
                else
                    dap_json_array_add(j_arr_data, j_obj_data);
            }
        }  
        if (l_continue) {
            dap_json_object_free(j_obj_tx);
            dap_json_object_free(j_arr_data);
            goto next_step;
        }            

        if (l_is_need_correction) {
            SUM_256_256(l_corr_value, l_fee_sum, &l_corr_value);
            const char *l_coins_str, *l_value_str = dap_uint256_to_const_char(l_corr_value, &l_coins_str);
            dap_json_object_add_string(l_corr_object, "recv_coins", l_coins_str);
            dap_json_object_add_string(l_corr_object, "recv_datoshi", l_value_str);
        }
        if (l_send_to_same_cond && l_found_out_to_same_addr_from_out_cond) {
            uint256_t l_cond_recv_value = l_cond_value;
            dap_json_t *l_cond_send_value_obj = NULL;
            dap_json_object_get_ex(l_cond_send_object, "send_datoshi", &l_cond_send_value_obj);
            const char *l_cond_send_value_str = dap_json_get_string(l_cond_send_value_obj);
            uint256_t l_cond_send_value = dap_uint256_scan_uninteger(l_cond_send_value_str);
            int l_direction = compare256(l_cond_recv_value, l_cond_send_value);
            if (l_direction > 0) {
                SUBTRACT_256_256(l_cond_recv_value, l_cond_send_value, &l_cond_recv_value);
                const char *l_coins_str, *l_value_str = dap_uint256_to_const_char(l_cond_recv_value, &l_coins_str);
                dap_json_object_add_string(l_cond_recv_object, "recv_coins", l_coins_str);
                dap_json_object_add_string(l_cond_recv_object, "recv_datoshi", l_value_str);
                dap_json_array_add(j_arr_data, l_cond_recv_object);
            } else if (l_direction < 0) {
                SUBTRACT_256_256(l_cond_send_value, l_cond_recv_value, &l_cond_send_value);
                const char *l_coins_str, *l_value_str = dap_uint256_to_const_char(l_cond_send_value, &l_coins_str);
                dap_json_object_add_string(l_cond_send_object, "send_coins", l_coins_str);
                dap_json_object_add_string(l_cond_send_object, "send_datoshi", l_value_str);
                dap_json_array_add(j_arr_data, l_cond_send_object);
            }
        } else if (l_recv_from_cond)
            dap_json_array_add(j_arr_data, l_cond_recv_object);

        if (dap_json_array_length(j_arr_data) > 0) {
            dap_json_object_add_object(j_obj_tx, "data", j_arr_data);
            dap_json_array_add(json_obj_datum, j_obj_tx);
        } else {
            dap_json_object_free(j_arr_data);
            j_arr_data = NULL;
            dap_json_object_free(j_obj_tx);
        }
        dap_list_free(l_list_out_items);

next_step:
        if (!l_from_cache)
            l_datum = iter_direc(l_datum_iter);
        else
            l_cur_tx_cache = a_ledger->wallet_cache_iter_get_callback(l_wallet_cache_iter, cache_iter_direc);
    }
    if (l_datum_iter)
        a_chain->callback_datum_iter_delete(l_datum_iter);

    if (l_wallet_cache_iter && a_ledger->wallet_cache_iter_delete_callback)
        a_ledger->wallet_cache_iter_delete_callback(l_wallet_cache_iter);

    // delete hashes
    s_tx_hash_processed_ht_free(&l_tx_data_ht);
    
    // if no history
    if (dap_json_array_length(json_obj_datum) == 2) {
        dap_json_t *json_empty_tx = dap_json_object_new();
        if (!json_empty_tx) {
            dap_json_rpc_allocation_error(a_json_arr_reply);
            dap_json_object_free(json_obj_datum);
            return NULL;
        }
        dap_json_object_add_string(json_empty_tx, "status", "empty");        
        dap_json_array_add(json_obj_datum, json_empty_tx);
    }    
    dap_json_object_add_string(json_obj_summary, "network", a_ledger->name);
    dap_json_object_add_string(json_obj_summary, "chain", a_chain->name);
    dap_json_object_add_int(json_obj_summary, a_version == 1 ? "accepted_tx" : "tx_accept_count", l_tx_ledger_accepted);
    dap_json_object_add_int(json_obj_summary, a_version == 1 ? "rejected_tx" : "tx_reject_count", l_tx_ledger_rejected);
    dap_json_object_add_int(json_obj_summary, a_version == 1 ? "tx_sum" : "tx_count", l_count);   
    dap_json_object_add_int(json_obj_summary, "total_tx_count", i_tmp);  
    return json_obj_datum;
}

static int s_json_tx_history_pack(dap_json_t *a_json_arr_reply, dap_json_t** a_json_obj_datum, dap_chain_datum_iter_t *a_datum_iter,
                                  dap_chain_datum_t * a_datum,
                                  dap_chain_t *a_chain, dap_ledger_t *a_ledger, dap_chain_tx_tag_action_type_t a_action,
                                  const char *a_hash_out_type, bool a_out_brief, size_t* a_accepted,
                                  size_t* a_rejected, bool a_look_for_unknown_service, const char *a_srv, int a_version)
{
    dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t*)a_datum->data;
    dap_hash_sha3_256_t l_ttx_hash = a_datum_iter->cur_hash ? *a_datum_iter->cur_hash : (dap_hash_sha3_256_t){0};

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

    *a_json_obj_datum = s_tx_history_to_json(a_json_arr_reply, &l_ttx_hash, NULL, l_tx, a_chain, a_ledger, a_hash_out_type, a_datum_iter, a_datum_iter->ret_code, a_out_brief, a_version);
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

dap_json_t *dap_db_history_tx_all(dap_json_t *a_json_arr_reply, dap_chain_t *a_chain, dap_chain_net_t *a_net,
                                  const char *a_hash_out_type, dap_json_t *json_obj_summary,
                                   size_t a_limit, size_t a_offset, bool out_brief,
					const char *a_srv, dap_chain_tx_tag_action_type_t a_action, bool a_head, int a_version)
{
        log_it(L_DEBUG, "Start getting tx from chain");
        dap_ledger_t *l_ledger = a_net->pub.ledger;
        size_t
            l_tx_ledger_accepted = 0,
            l_tx_ledger_rejected = 0,
            l_count = 0,
            i_tmp = 0;
        int res = 0;        
        dap_json_t *json_arr_out = dap_json_array_new();
        dap_json_t *json_tx_history = NULL;        
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
            res = s_json_tx_history_pack(a_json_arr_reply, &json_tx_history, l_datum_iter, l_datum, a_chain, l_ledger, a_action, a_hash_out_type, out_brief,
                                        &l_tx_ledger_accepted, &l_tx_ledger_rejected, look_for_unknown_service, a_srv, a_version);
            if (res == 1)
                continue;
            else if (res == 2)
            {
                dap_json_object_free(json_arr_out);
                return NULL;
            }
            dap_json_object_add_uint64(json_tx_history, a_version == 1 ? "tx number" : "tx_num", l_count+1);                     
            dap_json_array_add(json_arr_out, json_tx_history);
            ++i_tmp;
            l_count++;            
        }        
        log_it(L_DEBUG, "END getting tx from chain");
        a_chain->callback_datum_iter_delete(l_datum_iter);

        dap_json_object_add_string(json_obj_summary, "network", a_net->pub.name);
        dap_json_object_add_string(json_obj_summary, "chain", a_chain->name);
        dap_json_object_add_int(json_obj_summary, "tx_sum", l_count);
        dap_json_object_add_int(json_obj_summary, "accepted_tx", l_tx_ledger_accepted);
        dap_json_object_add_int(json_obj_summary, "rejected_tx", l_tx_ledger_rejected);
        return json_arr_out;
}

dap_json_t *s_get_ticker(dap_json_t *a_jobj_tickers, const char *a_token_ticker) {
    dap_json_t *l_result = NULL;
    dap_json_object_get_ex(a_jobj_tickers, a_token_ticker, &l_result);
    return l_result;
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
static dap_json_t *dap_db_chain_history_token_list(dap_json_t *a_json_arr_reply, dap_chain_t * a_chain, dap_ledger_t *a_ledger, const char *a_token_name, const char *a_hash_out_type, size_t *a_token_num, int a_version)
{
    dap_json_t *l_jobj_tickers = dap_json_object_new();
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
        dap_json_t *l_jobj_ticker = s_get_ticker(l_jobj_tickers, l_token->ticker);
        dap_json_t *l_jobj_decls = NULL;
        dap_json_t *l_jobj_updates = NULL;
        if (!l_jobj_ticker) {
            l_jobj_ticker = dap_json_object_new();
            // Use passed ledger instead of getting from net
            dap_json_t *l_current_state = dap_ledger_token_info_by_name(a_ledger, l_token->ticker, a_version);
            dap_json_object_add_object(l_jobj_ticker, a_version == 1 ? "current state" : "current_state", l_current_state);
            l_jobj_decls = dap_json_array_new();
            l_jobj_updates = dap_json_array_new();
            dap_json_object_add_object(l_jobj_ticker, "declarations", l_jobj_decls);
            dap_json_object_add_object(l_jobj_ticker, "updates", l_jobj_updates);
            dap_json_object_add_object(l_jobj_tickers, l_token->ticker, l_jobj_ticker);
            l_token_num++;
        } else {
            dap_json_object_get_ex(l_jobj_ticker, "declarations", &l_jobj_decls);
            dap_json_object_get_ex(l_jobj_ticker, "updates", &l_jobj_updates);
        }
        int l_ret_code = l_datum_iter->ret_code;
        dap_json_t *json_history_token = dap_json_object_new();
        dap_json_object_add_string(json_history_token, "status", l_ret_code ? "DECLINED" : "ACCEPTED");
dap_json_object_add_int(json_history_token, a_version == 1 ? "Ledger return code" : "ledger_ret_code", l_ret_code);
        switch (l_token->type) {
            case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_SIMPLE:
            case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_PUBLIC:
            case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_PRIVATE_DECL:
            case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_NATIVE_DECL:
            case DAP_CHAIN_DATUM_TOKEN_TYPE_DECL:
                dap_chain_datum_dump_json(a_json_arr_reply, json_history_token, l_datum, a_hash_out_type, a_chain->net_id, true, a_version);
                dap_json_array_add(l_jobj_decls, json_history_token);
                break;
            case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_PRIVATE_UPDATE:
            case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_NATIVE_UPDATE:
            case DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE:
                dap_chain_datum_dump_json(a_json_arr_reply, json_history_token, l_datum, a_hash_out_type, a_chain->net_id, false, a_version);
                dap_json_array_add(l_jobj_updates, json_history_token);
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

static size_t dap_db_net_history_token_list(dap_json_t *a_json_arr_reply, dap_ledger_t *a_ledger, const char *a_token_name, const char *a_hash_out_type, dap_json_t *a_obj_out, int a_version) {
    size_t l_token_num_total = 0;
    dap_json_t *json_arr_obj_tx = dap_json_array_new();
    
    // Iterate through registered chains in ledger
    dap_chain_info_t *l_chain_info, *l_tmp;
    dap_ht_foreach(a_ledger->chains_registry, l_chain_info, l_tmp) {
        dap_chain_t *l_chain_cur = (dap_chain_t *)l_chain_info->chain_ptr;
        if (!l_chain_cur) continue;
        
        size_t l_token_num = 0;
        dap_json_t *json_obj_tx = NULL;
        json_obj_tx = dap_db_chain_history_token_list(a_json_arr_reply, l_chain_cur, a_ledger, a_token_name, a_hash_out_type, &l_token_num, a_version);
        if(json_obj_tx)
            dap_json_array_add(json_arr_obj_tx, json_obj_tx);
        l_token_num_total += l_token_num;
    }
    dap_json_object_add_object(a_obj_out, a_version == 1 ? "TOKENS" : "token_list", json_arr_obj_tx);
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
                                    dap_hash_sha3_256_t *a_current_hash,
                                    dap_hash_sha3_256_t *a_target_hash,
                                    size_t a_path_depth,
                                    size_t a_max_depth,
                                    dap_json_t *a_json_chain,
                                    const char *a_hash_out_type)
{
    static size_t l_target_depth = 0;
    // Check depth limit
    if (a_path_depth >= a_max_depth) {
        return false;
    }

    // Check if we found the target
    if (dap_hash_sha3_256_compare(a_current_hash, a_target_hash)) {
        // Found target! Add it to chain
        dap_json_t *l_json_tx = dap_json_object_new();
        
        if (dap_strcmp(a_hash_out_type, "base58") == 0) {
            const char *l_hash_base58 = dap_enc_base58_encode_hash_to_str_static(a_current_hash);
            dap_json_object_add_string(l_json_tx, "hash", l_hash_base58 ? l_hash_base58 : "");
        } else {
            const char *l_hash_hex = dap_hash_sha3_256_to_str_static(a_current_hash);
            dap_json_object_add_string(l_json_tx, "hash", l_hash_hex);
        }
        // Add previous output index information
        dap_json_object_add_string(l_json_tx, "prev_out_idx", "unavailable");
        l_target_depth = a_path_depth;
        dap_json_object_add_int(l_json_tx, "position", 1);
        dap_json_object_add_string(l_json_tx, "type", "start");
               
        dap_json_array_add(a_json_chain, l_json_tx);
        
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

        dap_hash_sha3_256_t *l_tx_prev_hash = NULL;
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
            dap_json_t *l_json_tx = dap_json_object_new();
            if (dap_strcmp(a_hash_out_type, "base58") == 0) {
                const char *l_hash_base58 = dap_enc_base58_encode_hash_to_str_static(a_current_hash);
                dap_json_object_add_string(l_json_tx, "hash", l_hash_base58 ? l_hash_base58 : "");
            } else {
                const char *l_hash_hex = dap_hash_sha3_256_to_str_static(a_current_hash);
                dap_json_object_add_string(l_json_tx, "hash", l_hash_hex);
            }
            // Add previous output index information
            dap_json_object_add_int(l_json_tx, "prev_out_idx", l_tx_out_prev_idx);
            dap_json_object_add_int(l_json_tx, "position", l_target_depth - a_path_depth + 1);
            if (a_path_depth == 0)
                dap_json_object_add_string(l_json_tx, "type", "target");
            else
                dap_json_object_add_string(l_json_tx, "type", "intermediate");
            
            // Found target in this branch - add current tx to chain and return success
            dap_json_array_add(a_json_chain, l_json_tx);
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
static int s_ledger_trace_chain(dap_ledger_t *a_ledger, dap_hash_sha3_256_t *a_hash_from, dap_hash_sha3_256_t *a_hash_to, 
                               const char *a_hash_out_type, size_t a_max_depth, dap_json_t *a_json_arr_reply)
{
    // Validate input parameters
    if (!a_ledger || !a_hash_from || !a_hash_to || !a_json_arr_reply) {
        dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"), "Invalid input parameters");
        return dap_cli_error_code_get("LEDGER_PARAM_ERR");
    }

    // Check if starting transaction exists
    dap_chain_datum_tx_t *l_start_tx = dap_ledger_tx_find_by_hash(a_ledger, a_hash_to);
    if (!l_start_tx) {
        dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_TX_HASH_ERR"), 
                              "Starting transaction %s not found in ledger", dap_hash_sha3_256_to_str_static(a_hash_to));
        return dap_cli_error_code_get("LEDGER_TX_HASH_ERR");
    }

    // Check if target transaction exists
    dap_chain_datum_tx_t *l_target_tx = dap_ledger_tx_find_by_hash(a_ledger, a_hash_from);
    if (!l_target_tx) {
        dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_TX_HASH_ERR"), 
                              "Target transaction %s not found in ledger", dap_hash_sha3_256_to_str_static(a_hash_from));
        return dap_cli_error_code_get("LEDGER_TX_HASH_ERR");
    }

    // Create result JSON object
    dap_json_t *l_json_result = dap_json_object_new();
    dap_json_t *l_json_info = dap_json_object_new();
    dap_json_t *l_json_chain = dap_json_array_new();

    // Add info about the trace
    dap_json_object_add_string(l_json_info, "start_hash", dap_hash_sha3_256_to_str_static(a_hash_from));
    dap_json_object_add_string(l_json_info, "target_hash", dap_hash_sha3_256_to_str_static(a_hash_to));
    dap_json_object_add_string(l_json_info, "direction", "backward");
    dap_json_object_add_int(l_json_info, "max_depth", a_max_depth);
    dap_json_object_add_object(l_json_result, "trace_info", l_json_info);

    // Start recursive search
    bool l_found = s_ledger_trace_recursive(a_ledger, a_hash_to, a_hash_from,
                                           0, a_max_depth,
                                           l_json_chain, a_hash_out_type);

    // Add results to main JSON
    dap_json_object_add_object(l_json_result, "chain", l_json_chain);
    dap_json_object_add_int(l_json_result, "chain_length", dap_json_array_length(l_json_chain));
    dap_json_object_add_object(l_json_result, "target_found", dap_json_object_new_bool(l_found));
    
    if (!l_found) {
        dap_json_object_add_object(l_json_result, "status", 
                              dap_json_object_new_string("No path found from start to target transaction"));
    } else {
        dap_json_object_add_object(l_json_result, "status", 
                              dap_json_object_new_string("Path found from start to target transaction"));
    }

    dap_json_array_add(a_json_arr_reply, l_json_result);
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
int com_ledger(int a_argc, char ** a_argv, dap_json_t *a_json_arr_reply, int a_version)
{
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
        dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"), "invalid parameter -H, valid values: -H <hex | base58>");
        return dap_cli_error_code_get("LEDGER_PARAM_ERR");
    }

    //switch ledger params list | tx | info | trace
    int l_cmd = CMD_NONE;
    if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, arg_index + 1, "list", NULL)){
        l_cmd = CMD_LIST;
    } else if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "info", NULL))
        l_cmd = CMD_TX_INFO;
    else if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "trace", NULL))
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
            dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"), 
                                  "Subcommand 'event' requires subcommand 'list', 'dump', 'create' or 'key'");
            return dap_cli_error_code_get("LEDGER_PARAM_ERR");
        }
        
        if (l_subcmd == SUBCMD_CREATE) {
            dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-net", &l_net_str);
            if (l_net_str == NULL) {
                dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_NET_PARAM_ERR"), "Command requires key -net");
                return dap_cli_error_code_get("LEDGER_NET_PARAM_ERR");
            }
            
            // Get ledger by net name instead of net
            dap_ledger_t *l_ledger = dap_ledger_find_by_name(l_net_str);
            if (!l_ledger) {
                dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_NET_FIND_ERR"), "Can't find net %s", l_net_str);
                return dap_cli_error_code_get("LEDGER_NET_FIND_ERR");
            }
            
            // Получаем обязательные параметры для формирования транзакции-события
            const char *l_chain_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-chain", &l_chain_str);
            
            const char *l_wallet_name = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-w", &l_wallet_name);
            if (!l_wallet_name) {
                dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"), "Parameter -w is required to specify wallet");
                return dap_cli_error_code_get("LEDGER_PARAM_ERR");
            }
            
            const char *l_service_key_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-service_key", &l_service_key_str);
            if (!l_service_key_str) {
                dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"), "Parameter -service_key is required");
                return dap_cli_error_code_get("LEDGER_PARAM_ERR");
            }
            
            const char *l_group_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-group", &l_group_str);
            if (!l_group_str) {
                dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"), "Parameter -group is required");
                return dap_cli_error_code_get("LEDGER_PARAM_ERR");
            }
            
            const char *l_event_type_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-event_type", &l_event_type_str);
            if (!l_event_type_str) {
                dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"), "Parameter -event_type is required");
                return dap_cli_error_code_get("LEDGER_PARAM_ERR");
            }
            uint16_t l_event_type = dap_chain_tx_item_event_type_from_str(l_event_type_str);
            if (l_event_type == (uint16_t)-1) {
                l_event_type = strtoul(l_event_type_str, NULL, 10);
                if (!l_event_type) {
                    dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"), "Parameter -event_type is not recognized as standard type ot integer value");
                    return dap_cli_error_code_get("LEDGER_PARAM_ERR");
                }
            }
            
            const char *l_event_data_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-event_data", &l_event_data_str);
            
            const char *l_fee_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-fee", &l_fee_str);
            uint256_t l_fee = dap_chain_balance_scan(l_fee_str ? l_fee_str : "0");
            
            dap_cert_t *l_service_key = dap_cert_find_by_name(l_service_key_str);
            if (!l_service_key) {
                dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"), "Can't find cert %s", l_service_key_str);
                return dap_cli_error_code_get("LEDGER_PARAM_ERR");
            }
            const char *l_srv_uid_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-srv_uid", &l_srv_uid_str);
            if (!l_srv_uid_str) {
                dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"), "Parameter -srv_uid is required");
                return dap_cli_error_code_get("LEDGER_PARAM_ERR");
            }
            dap_chain_srv_uid_t l_srv_uid = dap_chain_srv_uid_from_str(l_srv_uid_str);
            if (!l_srv_uid.uint64) {
                dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"), "Can't find service UID %s", l_srv_uid_str);
                return dap_cli_error_code_get("LEDGER_PARAM_ERR");
            }

            // Get chain from ledger's chain registry
            dap_chain_t *l_chain = NULL;
            if (l_chain_str) {
                dap_chain_info_t *l_chain_info = dap_ledger_get_chain_info_by_name(l_ledger, l_chain_str);
                if (l_chain_info)
                    l_chain = (dap_chain_t *)l_chain_info->chain_ptr;
            } else {
                // Find default TX chain
                dap_chain_info_t *l_chain_info = NULL, *l_tmp = NULL;
                dap_ht_foreach(l_ledger->chains_registry, l_chain_info, l_tmp) {
                    if (l_chain_info->chain_type == CHAIN_TYPE_TX) {
                        l_chain = (dap_chain_t *)l_chain_info->chain_ptr;
                        break;
                    }
                }
            }
            if (!l_chain) {
                dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"), 
                                      "Can't find chain %s in net %s", l_chain_str ? l_chain_str : "tx", l_net_str);
                return dap_cli_error_code_get("LEDGER_PARAM_ERR");
            }
            
            // Подготавливаем данные события
            void *l_event_data = NULL;
            size_t l_event_data_size = 0;
            
            if (l_event_data_str) {
                l_event_data = DAP_NEW_SIZE(uint8_t, strlen(l_event_data_str) + 1);
                if (!l_event_data) {
                    dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"), "Memory allocation error");
                    return dap_cli_error_code_get("LEDGER_PARAM_ERR");
                }
                strcpy(l_event_data, l_event_data_str);
                l_event_data_size = strlen(l_event_data_str) + 1;
            }
            
            // TODO: Migrate to new TX Compose API
            // This requires:
            // 1. Find UTXO via dap_ledger_get_utxo_for_value()
            // 2. Prepare event params structure
            // 3. Call dap_chain_tx_compose_create("event", ...)
            // 4. Add result datum to mempool via ledger callback
            
            dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"), 
                                  "Event TX creation temporarily disabled - migration to TX Compose API in progress");
            DAP_DEL_Z(l_event_data);
            return dap_cli_error_code_get("LEDGER_PARAM_ERR");
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
                dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"),
                                      "Command 'event key' requires subcommand 'add', 'remove' or 'list'");
                return dap_cli_error_code_get("LEDGER_PARAM_ERR");
            }
            
            dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-net", &l_net_str);
            if (l_net_str == NULL) {
                dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_NET_PARAM_ERR"), "Command requires key -net");
                return dap_cli_error_code_get("LEDGER_NET_PARAM_ERR");
            }
            
            dap_ledger_t *l_ledger = dap_ledger_find_by_name(l_net_str);
            if (l_ledger == NULL) {
                dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_LACK_ERR"), "Can't get ledger for net %s", l_net_str);
                return dap_cli_error_code_get("LEDGER_LACK_ERR");
            }
            
            if (l_key_subcmd == KEY_SUBCMD_LIST) {
                dap_json_t *l_json_obj_out = dap_json_object_new();
                dap_json_t *l_json_array_keys = dap_json_array_new();
                
                dap_list_t *l_list = dap_ledger_event_pkey_list(l_ledger);
                if (l_list) {
                    for (dap_list_t *l_item = l_list; l_item; l_item = l_item->next) {
                        dap_hash_sha3_256_t *l_hash = (dap_hash_sha3_256_t *)l_item->data;
                        const char *l_hash_str = dap_strcmp(l_hash_out_type, "hex") 
                                           ? dap_enc_base58_encode_hash_to_str_static(l_hash)
                                           : dap_hash_sha3_256_to_str_static(l_hash);
                        dap_json_array_add(l_json_array_keys, dap_json_object_new_string(l_hash_str));
                    }
                    
                    // Free the list and its elements
                    dap_list_free_full(l_list, free);
                }
                
                dap_json_object_add_object(l_json_obj_out, "keys", l_json_array_keys);
                dap_json_array_add(a_json_arr_reply, l_json_obj_out);
                return 0;
            } else { // ADD or REMOVE key
                const char *l_pkey_hash_str = NULL;
                dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-hash", &l_pkey_hash_str);
                if (!l_pkey_hash_str) {
                    dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"), 
                                          "Command requires parameter -hash for key hash");
                    return dap_cli_error_code_get("LEDGER_PARAM_ERR");
                }
                
                dap_hash_sha3_256_t l_pkey_hash = {};
                if (dap_hash_sha3_256_from_str(l_pkey_hash_str, &l_pkey_hash)) {
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_HASH_ERR, 
                                          "Invalid hash string format");
                    return DAP_CHAIN_NODE_CLI_COM_LEDGER_HASH_ERR;
                }
                
                int l_res = -1;
                const char *l_action = NULL;
                
                // Get certs for signing the decree
                const char *l_certs_str = NULL;
                dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-certs", &l_certs_str);
                if (!l_certs_str) {
                    dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"),
                                        "Parameter -certs is required to sign the decree");
                    return dap_cli_error_code_get("LEDGER_PARAM_ERR");
                }

                // Get certificates for signing
                char **l_certs_array = NULL;
                uint16_t l_certs_count = 0;
                dap_cert_t **l_certs = NULL;
                if (l_certs_str && strlen(l_certs_str) > 0) {
                    l_certs_array = dap_strsplit(l_certs_str, ",", -1);
                    if (!l_certs_array) {
                        dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"),
                                            "Can't parse certs");
                        return dap_cli_error_code_get("LEDGER_PARAM_ERR");
                    }
                    for(l_certs_count = 0; l_certs_array[l_certs_count]; l_certs_count++);
                    l_certs = DAP_NEW_SIZE(dap_cert_t*, sizeof(dap_cert_t*) * l_certs_count);
                    for(uint16_t i = 0; i < l_certs_count; i++) {
                        l_certs[i] = dap_cert_find_by_name(l_certs_array[i]);
                        if(!l_certs[i]){
                            dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"),
                                                "Can't find cert \"%s\"", l_certs_array[i]);
                            DAP_DELETE(l_certs);
                            dap_strfreev(l_certs_array);
                            return dap_cli_error_code_get("LEDGER_PARAM_ERR");
                        }
                    }
                } else {
                    dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"), 
                                            "Parameter -certs is required");
                    return dap_cli_error_code_get("LEDGER_PARAM_ERR");
                }

                // Get decree chain from ledger's chain registry
                dap_chain_t *l_chain = NULL;
                dap_chain_info_t *l_chain_info, *l_tmp;
                dap_ht_foreach(l_ledger->chains_registry, l_chain_info, l_tmp) {
                    if (l_chain_info->chain_type == CHAIN_TYPE_DECREE) {
                        l_chain = (dap_chain_t *)l_chain_info->chain_ptr;
                        break;
                    }
                }
                
                if (!l_chain) {
                    dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_NO_DECREE_CHAIN"),
                                            "Network doesn't have a decree chain");
                    DAP_DELETE(l_certs);
                    dap_strfreev(l_certs_array);
                    return dap_cli_error_code_get("LEDGER_NO_DECREE_CHAIN");
                }
                dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-chain", &l_target_chain_str);
                // Get target chain from ledger's chain registry
                dap_chain_t *l_target_chain = NULL;
                if (l_target_chain_str) {
                    dap_chain_info_t *l_chain_info = dap_ledger_get_chain_info_by_name(l_ledger, l_target_chain_str);
                    if (l_chain_info)
                        l_target_chain = (dap_chain_t *)l_chain_info->chain_ptr;
                } else {
                    // Find default TX chain
                    dap_chain_info_t *l_chain_info = NULL, *l_tmp = NULL;
                    dap_ht_foreach(l_ledger->chains_registry, l_chain_info, l_tmp) {
                        if (l_chain_info->chain_type == CHAIN_TYPE_TX) {
                            l_target_chain = (dap_chain_t *)l_chain_info->chain_ptr;
                            break;
                        }
                    }
                }
                if (!l_target_chain) {
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_NO_ANCHOR_CHAIN,
                                            "Network %s doesn't have a chain %s", l_net_str, l_target_chain_str ? l_target_chain_str : "type tx");
                    return DAP_CHAIN_NODE_CLI_COM_LEDGER_NO_ANCHOR_CHAIN;
                }
                size_t l_tsd_size = sizeof(dap_tsd_t) + sizeof(dap_hash_sha3_256_t); 
                // Create a decree
                size_t l_decree_size = sizeof(dap_chain_datum_decree_t) + l_tsd_size;
                dap_chain_datum_decree_t *l_decree = DAP_NEW_Z_SIZE(dap_chain_datum_decree_t, l_decree_size);
                l_decree->decree_version = DAP_CHAIN_DATUM_DECREE_VERSION;
                l_decree->header.ts_created = dap_time_now();
                l_decree->header.type = DAP_CHAIN_DATUM_DECREE_TYPE_COMMON;
                l_decree->header.common_decree_params.net_id = l_ledger->net_id;
                l_decree->header.common_decree_params.chain_id = l_target_chain->id;
                // Use callback to get current cell_id (defaults to zero if not set)
                l_decree->header.common_decree_params.cell_id = l_ledger->get_cur_cell_callback ? 
                                                                 l_ledger->get_cur_cell_callback(l_ledger) : 
                                                                 (dap_chain_cell_id_t){.uint64 = 0};
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
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_SIGNING_FAILED,
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
                    dap_json_t *l_json_object = dap_json_object_new();
                    dap_json_object_add_string(l_json_object, "status", "success");
                    dap_json_object_add_string(l_json_object, "action", l_key_subcmd == KEY_SUBCMD_ADD ? "add" : "remove");
                    dap_json_object_add_string(l_json_object, "decree_datum", l_key_str_out);
                    dap_json_array_add(a_json_arr_reply, l_json_object);
                    DAP_DELETE(l_key_str_out);
                    return 0;
                } else {
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_MEMPOOL_FAILED, "Failed to add decree to mempool");
                    return DAP_CHAIN_NODE_CLI_COM_LEDGER_MEMPOOL_FAILED;
                }
            }
                
        } else if (l_subcmd == SUBCMD_LIST) {
            dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-net", &l_net_str);
            if (l_net_str == NULL) {
                dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_NET_PARAM_ERR"), "Command requires key -net");
                return dap_cli_error_code_get("LEDGER_NET_PARAM_ERR");
            }
            
            dap_ledger_t *l_ledger = dap_ledger_find_by_name(l_net_str);
            if (l_ledger == NULL) {
                dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_LACK_ERR"), "Can't get ledger for net %s", l_net_str);
                return dap_cli_error_code_get("LEDGER_LACK_ERR");
            }
            
            // Get list of all events
            const char *l_group_name = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-group", &l_group_name);
            
            dap_json_t *l_json_obj_out = dap_json_object_new();
            dap_json_t *l_json_arr_events = dap_json_array_new();
            
            // Get events for specific group or all events
            dap_list_t *l_events = dap_ledger_event_get_list(l_ledger, l_group_name);
            if (l_events) {
                for (dap_list_t *l_item = l_events; l_item; l_item = l_item->next) {
                    dap_chain_tx_event_t *l_event = (dap_chain_tx_event_t *)l_item->data;
                    dap_json_t *l_json_event = dap_json_object_new();
                    dap_chain_datum_tx_event_to_json(l_json_event, l_event, l_hash_out_type);
                    dap_json_array_add(l_json_arr_events, l_json_event);
                }
                
                // Free the list and its elements
                dap_list_free_full(l_events, dap_chain_tx_event_delete);
            }

            dap_json_object_add_object(l_json_obj_out, "events", l_json_arr_events);
            dap_json_array_add(a_json_arr_reply, l_json_obj_out);
            return 0;
        } else if (l_subcmd == SUBCMD_DUMP) {
            dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-net", &l_net_str);
            if (l_net_str == NULL) {
                dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_NET_PARAM_ERR"), "Command requires key -net");
                return dap_cli_error_code_get("LEDGER_NET_PARAM_ERR");
            }
            
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-hash", &l_tx_hash_str);
            if (!l_tx_hash_str) {
                dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"), 
                                      "Command 'event dump' requires parameter -hash for tx hash");
                return dap_cli_error_code_get("LEDGER_PARAM_ERR");
            }
            
            dap_ledger_t *l_ledger = dap_ledger_find_by_name(l_net_str);
            if (l_ledger == NULL) {
                dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_LACK_ERR"), "Can't get ledger for net %s", l_net_str);
                return dap_cli_error_code_get("LEDGER_LACK_ERR");
            }
            
            dap_hash_sha3_256_t l_tx_hash = {};
            if (dap_hash_sha3_256_from_str(l_tx_hash_str, &l_tx_hash)) {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_HASH_ERR, 
                                      "Invalid hash string format");
                return DAP_CHAIN_NODE_CLI_COM_LEDGER_HASH_ERR;
            }
            
            dap_chain_tx_event_t *l_event = dap_ledger_event_find(l_ledger, &l_tx_hash);
            if (!l_event) {
                dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_LACK_ERR"), 
                                      "Event not found for tx hash %s", l_tx_hash_str);
                return dap_cli_error_code_get("LEDGER_LACK_ERR");
            }
            
            dap_json_t *l_json_obj_out = dap_json_object_new();
            dap_chain_datum_tx_event_to_json(l_json_obj_out, l_event, l_hash_out_type);
            dap_json_array_add(a_json_arr_reply, l_json_obj_out);
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
                dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"), 
                                      "Invalid depth parameter. Must be a number between 1 and 10000");
                return dap_cli_error_code_get("LEDGER_PARAM_ERR");
            }
            l_max_depth = (size_t)l_parsed_depth;
        }
        
        // Validate required parameters
        if (!l_hash_from_str) {
            dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"), 
                                  "Command 'trace' requires parameter -from");
            return dap_cli_error_code_get("LEDGER_PARAM_ERR");
        }
        if (!l_hash_to_str) {
            dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"), 
                                  "Command 'trace' requires parameter -to");
            return dap_cli_error_code_get("LEDGER_PARAM_ERR");
        }
        
        // Parse target hash (hash1)
        dap_hash_sha3_256_t l_hash_from = {};
        if (dap_hash_sha3_256_from_str(l_hash_from_str, &l_hash_from)) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_HASH_GET_ERR, 
                                "Can't parse target hash %s", l_hash_from_str);
            return DAP_CHAIN_NODE_CLI_COM_LEDGER_HASH_GET_ERR;
        }

        // Parse starting hash (hash2)
        dap_hash_sha3_256_t l_hash_to = {};
        if (dap_hash_sha3_256_from_str(l_hash_to_str, &l_hash_to)) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_HASH_GET_ERR, 
                                "Can't parse starting hash %s", l_hash_to_str);
            return DAP_CHAIN_NODE_CLI_COM_LEDGER_HASH_GET_ERR;
        }
        if (!l_net_str) {
            dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_NET_PARAM_ERR"), 
                                  "Command 'trace' requires parameter -net");
            return dap_cli_error_code_get("LEDGER_NET_PARAM_ERR");
        }
        // Get ledger
        dap_ledger_t *l_ledger = dap_ledger_find_by_name(l_net_str);
        if (!l_ledger) {
            dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_LACK_ERR"), 
                                  "Can't get ledger for net %s", l_net_str);
            return dap_cli_error_code_get("LEDGER_LACK_ERR");
        }

        // Execute trace
        return s_ledger_trace_chain(l_ledger, &l_hash_from, &l_hash_to, l_hash_out_type, l_max_depth, a_json_arr_reply);
        
    } else if(l_cmd == CMD_LIST){
        enum {SUBCMD_NONE, SUBCMD_LIST_COIN, SUB_CMD_LIST_LEDGER_THRESHOLD, SUB_CMD_LIST_LEDGER_BALANCE, SUB_CMD_LIST_LEDGER_THRESHOLD_WITH_HASH};
        int l_sub_cmd = SUBCMD_NONE;
        dap_hash_sha3_256_t l_tx_threshold_hash = {};
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
                if (dap_hash_sha3_256_from_str(l_tx_threshold_hash_str, &l_tx_threshold_hash)){
                    l_tx_hash_str = NULL;
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_TRESHOLD_ERR, "tx threshold hash not recognized");
                    return DAP_CHAIN_NODE_CLI_COM_LEDGER_TRESHOLD_ERR;
                }
            }
        }
        if (l_sub_cmd == SUBCMD_NONE) {
            dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"), "Command 'list' requires subcommands 'coins' or 'threshold'");
            return dap_cli_error_code_get("LEDGER_PARAM_ERR");
        }
        dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-net", &l_net_str);
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-limit", &l_limit_str);
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-offset", &l_offset_str);
        bool l_head = dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-head", &l_head_str) ? true : false;
        size_t l_limit = l_limit_str ? strtoul(l_limit_str, NULL, 10) : 0;
        size_t l_offset = l_offset_str ? strtoul(l_offset_str, NULL, 10) : 0;
        if (l_net_str == NULL){
            dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_NET_PARAM_ERR"), "Command 'list' requires key -net");
            return dap_cli_error_code_get("LEDGER_NET_PARAM_ERR");
        }
        dap_ledger_t *l_ledger = dap_ledger_find_by_name(l_net_str);
        if (l_ledger == NULL){
            dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_LACK_ERR"), "Can't get ledger for net %s", l_net_str);
            return dap_cli_error_code_get("LEDGER_LACK_ERR");
        }
        if (l_sub_cmd == SUB_CMD_LIST_LEDGER_THRESHOLD) {
            dap_json_t *json_obj_out = dap_ledger_threshold_info(l_ledger, l_limit, l_offset, NULL, l_head, a_version);
            if (json_obj_out){
                dap_json_array_add(a_json_arr_reply, json_obj_out);
            }
            return 0;
        }
        if (l_sub_cmd == SUB_CMD_LIST_LEDGER_THRESHOLD_WITH_HASH) {
            dap_json_t *json_obj_out = dap_ledger_threshold_info(l_ledger, 0, 0, &l_tx_threshold_hash, l_head, a_version);
            if (json_obj_out){
                dap_json_array_add(a_json_arr_reply, json_obj_out);
            }
            return 0;
        }
        if (l_sub_cmd == SUB_CMD_LIST_LEDGER_BALANCE) {
            dap_json_t *json_obj_out = dap_ledger_balance_info(l_ledger, l_limit, l_offset, l_head, a_version);
            if (json_obj_out){
                dap_json_array_add(a_json_arr_reply, json_obj_out);
            }
            return 0;
        }
        dap_json_t *json_obj_datum = dap_ledger_token_info(l_ledger, l_limit, l_offset, a_version);

        if (json_obj_datum) {
            dap_json_array_add(a_json_arr_reply, json_obj_datum);
        }
        return 0;
    } else if (l_cmd == CMD_TX_INFO){
        //GET hash
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-hash", &l_tx_hash_str);
        //get net
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_str);
        //get search type
        bool l_unspent_flag = dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-unspent", NULL);
        bool l_need_sign  = dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-need_sign", NULL);
        //check input
        if (l_tx_hash_str == NULL){
            dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"), "Subcommand 'info' requires key -hash");
            return dap_cli_error_code_get("LEDGER_PARAM_ERR");
        }
        if (l_net_str == NULL){
            dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_NET_PARAM_ERR"), "Subcommand 'info' requires key -net");
            return dap_cli_error_code_get("LEDGER_NET_PARAM_ERR");
        }
        // Get ledger by net name instead of net
        dap_ledger_t *l_ledger = dap_ledger_find_by_name(l_net_str);
        if (!l_ledger) {
            dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_NET_FIND_ERR"), "Can't find net %s", l_net_str);
            return dap_cli_error_code_get("LEDGER_NET_FIND_ERR");
        }
        dap_hash_sha3_256_t *l_tx_hash = DAP_NEW(dap_hash_sha3_256_t);
        if (dap_hash_sha3_256_from_str(l_tx_hash_str, l_tx_hash)) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_HASH_GET_ERR, "Can't get hash_fast from %s, check that the hash is correct", l_tx_hash_str);
            DAP_DEL_Z(l_tx_hash);
            return DAP_CHAIN_NODE_CLI_COM_LEDGER_HASH_GET_ERR;
        }
        // Use ledger's TX find function directly
        dap_chain_datum_tx_t *l_datum_tx = dap_ledger_tx_find_by_hash(l_ledger, l_tx_hash);
        if (l_datum_tx == NULL) {
            dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_TX_HASH_ERR"), "Can't find datum for transaction hash %s in chains", l_tx_hash_str);
            DAP_DEL_Z(l_tx_hash);
            return dap_cli_error_code_get("LEDGER_TX_HASH_ERR");
        }
        dap_json_t *json_datum = dap_json_object_new();
        if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-tx_to_json", NULL)) {
            const char *l_ticker = dap_ledger_tx_get_token_ticker_by_hash(l_ledger, l_tx_hash);
            dap_json_object_add_string(json_datum, "token_ticker", l_ticker);
            bool l_all_outs_unspent = true;
            byte_t *l_item; size_t l_size; int index, l_out_idx = -1;
            dap_json_t *json_arr_items = dap_json_array_new();
            TX_ITEM_ITER_TX_TYPE(l_item, TX_ITEM_TYPE_OUT_ALL, l_size, index, l_datum_tx) {
                dap_hash_sha3_256_t l_spender = { };
                ++l_out_idx;
                if ( dap_ledger_tx_hash_is_used_out_item(l_ledger, l_tx_hash, l_out_idx, NULL) ) {
                    l_all_outs_unspent = false;
                    char l_hash_str[DAP_HASH_SHA3_256_STR_SIZE] = { '\0' };
                    dap_hash_sha3_256_to_str(&l_spender, l_hash_str, sizeof(l_hash_str));
                    dap_json_t *l_json_obj_datum = dap_json_object_new();
                    dap_json_object_add_int(l_json_obj_datum, "out_idx", l_out_idx);
                    dap_json_object_add_string(l_json_obj_datum, "spent_by_tx", l_hash_str);
                    dap_json_array_add(json_arr_items, l_json_obj_datum);
                }
            }
            dap_json_object_add_object(json_datum, "all_outs_unspent", dap_json_object_new_bool(l_all_outs_unspent));
            if (l_all_outs_unspent) {
                dap_json_object_free(json_arr_items);
            } else {
                dap_json_object_add_object(json_datum, "spent_or_coloured_outs", json_arr_items);
            }
            dap_chain_net_tx_to_json(l_datum_tx, json_datum);
            if (!dap_json_object_length(json_datum)) {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_TX_TO_JSON_ERR, "Can't find transaction hash %s in ledger", l_tx_hash_str);
                dap_json_object_free(json_datum);
                DAP_DELETE(l_tx_hash);
                return DAP_CHAIN_NODE_CLI_COM_LEDGER_TX_TO_JSON_ERR;
            }
            dap_json_array_add(a_json_arr_reply, json_datum);
            DAP_DELETE(l_tx_hash);
            return 0;
        }

        if (!s_dap_chain_datum_tx_out_data(a_json_arr_reply,l_datum_tx, l_ledger, json_datum, l_hash_out_type, l_tx_hash, a_version)){
            dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_TX_HASH_ERR"), "Can't find transaction hash %s in ledger", l_tx_hash_str);
            dap_json_object_free(json_datum);
            DAP_DEL_Z(l_tx_hash);
            return dap_cli_error_code_get("LEDGER_TX_HASH_ERR");
        }
        DAP_DELETE(l_tx_hash);

        if (json_datum){
            dap_json_array_add(a_json_arr_reply, json_datum);
        }        
    }
    else{
        dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"), "Command 'ledger' requires parameter 'list', 'info', or 'trace'");
        return dap_cli_error_code_get("LEDGER_PARAM_ERR");
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
int com_token(int a_argc, char ** a_argv, dap_json_t *a_json_arr_reply, int a_version)
{    
    enum { CMD_NONE, CMD_LIST, CMD_INFO, CMD_TX };
    int arg_index = 1;
    const char *l_net_str = NULL;
    dap_chain_net_t * l_net = NULL;
    dap_ledger_t *l_ledger = NULL;

    const char * l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    if (!l_hash_out_type)
        l_hash_out_type = "hex";
    if (dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_PARAM_ERR, "invalid parameter -H, valid values: -H <hex | base58>");
        return -DAP_CHAIN_NODE_CLI_COM_TOKEN_PARAM_ERR;
    }

    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_str);
    // Select chain network
    if(!l_net_str) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_PARAM_ERR, "command requires parameter '-net'");
        return -DAP_CHAIN_NODE_CLI_COM_TOKEN_PARAM_ERR;
    } else {
        // Get ledger by net name
        l_ledger = dap_ledger_find_by_name(l_net_str);
        if(l_ledger == NULL) { // Can't find such network
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_PARAM_ERR,
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
        dap_json_t *json_obj_tx = dap_json_object_new();
        size_t l_total_all_token = dap_db_net_history_token_list(a_json_arr_reply, l_ledger, NULL, l_hash_out_type, json_obj_tx, a_version);

        dap_json_object_length(json_obj_tx);
        dap_json_object_add_uint64(json_obj_tx, "tokens", l_total_all_token);
        dap_json_array_add(a_json_arr_reply, json_obj_tx);
        return 0;
    }
    // token info
    else if(l_cmd == CMD_INFO) {
        const char *l_token_name_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-name", &l_token_name_str);
        if(!l_token_name_str) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_PARAM_ERR, "command requires parameter '-name' <token name>");
            return -DAP_CHAIN_NODE_CLI_COM_TOKEN_PARAM_ERR;
        }
        dap_json_t *json_obj_tx = dap_json_object_new();
        if (!dap_db_net_history_token_list(a_json_arr_reply, l_ledger, l_token_name_str, l_hash_out_type, json_obj_tx, a_version)) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_FOUND_ERR, "token '%s' not found\n", l_token_name_str);\
            return -DAP_CHAIN_NODE_CLI_COM_TOKEN_UNKNOWN;
        }
        dap_json_array_add(a_json_arr_reply, json_obj_tx);
        return DAP_CHAIN_NODE_CLI_COM_TOKEN_OK;
    }
    // command tx history — disabled: requires migration to new chain enumeration API
    // (dap_chain_enum/dap_db_history_filter removed in 6.x, use dap_db_history_tx/dap_db_history_addr instead)
#if 0
    else if(l_cmd == CMD_TX) {
        tx_hash_processed_t *l_list_tx_hash_processd = NULL;
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
            dap_json_rpc_error_add(a_json_arr_reply, -1, "command requires parameter '-name' <token name>");
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
                    dap_ledger_t *l_ledger = dap_ledger_find_by_name(l_net_str);
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
            s_tx_hash_processed_ht_free(&l_list_tx_hash_processd);
            dap_json_rpc_error_add(a_json_arr_reply, 0, l_str_out->str);
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
                // Use wallet get_addr callback if registered
                if (!a_ledger->wallet_get_addr_callback) {
                    dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_get_code(DAP_LEDGER_CLI_ERROR_TX_NO_WALLET_GET_ADDR_FUNC),
                        "%s", dap_cli_error_get_str(DAP_LEDGER_CLI_ERROR_TX_NO_WALLET_GET_ADDR_FUNC));
                    return dap_cli_error_get_code(DAP_LEDGER_CLI_ERROR_TX_NO_WALLET_GET_ADDR_FUNC);
                }
                dap_chain_addr_t *l_addr_tmp = (dap_chain_addr_t *)a_ledger->wallet_get_addr_callback(l_wallet_name, a_ledger->net_id);
                if (!l_addr_tmp) {
                    dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_get_code(DAP_LEDGER_CLI_ERROR_MEMORY_ALLOC),
                        "Can't get addr from wallet %s", l_wallet_name);
                    return dap_cli_error_get_code(DAP_LEDGER_CLI_ERROR_MEMORY_ALLOC);
                }
                l_addr_base58 = DAP_NEW_SIZE(dap_chain_addr_t, sizeof(dap_chain_addr_t));
                memcpy(l_addr_base58, l_addr_tmp, sizeof(dap_chain_addr_t));
                    char *ffl_addr_base58 = dap_chain_addr_to_str_static(l_addr_base58);
                    ffl_addr_base58 = 0;
                }
                else {
                    char *l_reply_str = dap_strdup_printf("wallet '%s' not found", l_wallet_name);
                    dap_json_rpc_error_add(a_json_arr_reply, -1, l_reply_str);
                    DAP_DELETE(l_reply_str);
                    return -2;
                }
            }
            if(!l_addr_base58) {
                dap_json_rpc_error_add(a_json_arr_reply, -1, "address not recognized");
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
            dap_json_rpc_error_add(a_json_arr_reply, 0, l_str_out->str);
            dap_string_free(l_str_out, true);
            DAP_DELETE(l_addr_base58);
            return 0;

        }
        else{
            dap_json_rpc_error_add(a_json_arr_reply, -1, "not found parameter '-all', '-wallet' or '-addr'");
            return -1;
        }
    }
#endif

    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_UNKNOWN, "unknown command code %d", l_cmd);
    return -DAP_CHAIN_NODE_CLI_COM_TOKEN_UNKNOWN;
}

int dap_chain_ledger_cli_init(void)
{
    dap_cli_server_cmd_add("ledger", com_ledger, NULL,
                           "Ledger information",
                           -1,
                           "ledger list { coins | threshold | addrs | balance } -net <net_name>\n"
                           "ledger tx -all { -net <net_name> | -chain <chain_name> }\n"
                           "ledger tx -hash <tx_hash> -net <net_name>\n");
    dap_cli_server_cmd_add("token", com_token, NULL,
                           "Token information",
                           -1,
                           "token { list | info | tx } -net <net_name>\n");
    log_it(L_NOTICE, "Ledger CLI commands registered");
    return 0;
}

void dap_chain_ledger_cli_deinit(void)
{
    log_it(L_INFO, "Ledger CLI commands unregistered");
}
