/*
 * Authors:
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * Cellframe Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2019-2025
 * All rights reserved.
 *
 * This file is part of DAP (Distributed Applications Platform) the open source project
 *
 * DAP is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * DAP is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdbool.h>
#include <stddef.h>

#include "uthash.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_string.h"
#include "dap_list.h"
#include "dap_hash.h"
#include "dap_time.h"
#include "dap_enc_base58.h"
#include "dap_json.h"
#include "dap_json_rpc_errors.h"
#include "dap_math_ops.h"
#include "dap_math_convert.h"

#include "dap_cli_server.h"
#include "dap_cli_error_codes.h"

#include "dap_chain_common.h"
#include "dap_chain_datum.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_ledger.h"
#include "dap_chain_ledger_pvt.h"

#include "dap_chain_ledger_cli_tx_history.h"
#include "dap_chain_ledger_cli_internal.h"
#include "dap_chain_ledger_cli_error_codes.h"
#include "dap_chain_ledger_cli_compat.h"

#define LOG_TAG "ledger_cli_tx_history"

// Forward declarations for net functions
extern dap_chain_t* dap_chain_net_get_chain_by_name(void *a_net, const char *a_chain_name);
extern dap_chain_t* dap_chain_net_get_default_chain_by_chain_type(void *a_net, dap_chain_type_t a_chain_type);
extern void* dap_chain_net_by_id(dap_chain_net_id_t a_id);

/**
 * @brief Helper structure for tracking processed TX hashes
 */
typedef struct dap_chain_tx_hash_processed_ht {
    dap_chain_hash_fast_t hash;
    UT_hash_handle hh;
} dap_chain_tx_hash_processed_ht_t;

/**
 * @brief Free TX hash tracking table
 */
static void s_tx_hash_processed_ht_free(dap_chain_tx_hash_processed_ht_t **a_hash_processed)
{
    if (!a_hash_processed || !*a_hash_processed)
        return;
    dap_chain_tx_hash_processed_ht_t *l_tmp, *l_current;
    HASH_ITER(hh, *a_hash_processed, l_current, l_tmp) {
        HASH_DEL(*a_hash_processed, l_current);
        DAP_DELETE(l_current);
    }
}

/**
 * @brief Convert TX to JSON history format
 */
static dap_json_t *s_tx_history_to_json(dap_json_t *a_json_arr_reply,
                                         dap_chain_hash_fast_t *a_tx_hash,
                                         dap_hash_fast_t *l_atom_hash,
                                         dap_chain_datum_tx_t *l_tx,
                                         dap_chain_t *a_chain,
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

    // Add transaction creation time
    char l_time_str[DAP_TIME_STR_SIZE] = "unknown";
    if (l_tx->header.ts_created)
        dap_time_to_str_rfc822(l_time_str, DAP_TIME_STR_SIZE, l_tx->header.ts_created);

    dap_ledger_t *l_ledger = a_ledger;
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
                            : dap_chain_hash_fast_to_str_static(l_atom_hash);
        dap_json_object_add_string(json_obj_datum, "atom_hash", l_atom_hash_str);
        dap_chain_atom_iter_t *l_iter = a_chain->callback_atom_iter_create(a_chain, c_dap_chain_cell_id_null, l_atom_hash);
        size_t l_size = 0;
        if (a_chain->callback_atom_find_by_hash(l_iter, l_atom_hash, &l_size) != NULL) {
            uint64_t l_block_count = a_chain->callback_count_atom(a_chain);
            uint64_t l_confirmations = l_block_count - l_iter->cur_num;
            dap_json_object_add_uint64(json_obj_datum, "confirmations", l_confirmations);
        }
        a_chain->callback_atom_iter_delete(l_iter);
    }

    const char *l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                        ? dap_enc_base58_encode_hash_to_str_static(a_tx_hash)
                        : dap_chain_hash_fast_to_str_static(a_tx_hash);
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
    if (a_datum_iter) action = a_datum_iter->action;

    if (srv_found) {
        dap_json_object_add_string(json_obj_datum, "action", dap_ledger_tx_action_str(action));
    } else {
        dap_json_object_add_string(json_obj_datum, "action", "UNKNOWN");
    }
    dap_json_object_add_object(json_obj_datum, "batching", 
        dap_json_object_new_string(!dap_chain_datum_tx_item_get_tsd_by_type(l_tx, DAP_CHAIN_DATUM_TRANSFER_TSD_TYPE_OUT_COUNT) ? "false" : "true"));
    dap_json_object_add_string(json_obj_datum, a_version == 1 ? "tx created" : "tx_created", l_time_str);
    
    if (!brief_out) {
        dap_chain_datum_dump_tx_json(a_json_arr_reply, l_tx, l_tx_token_ticker ? l_tx_token_ticker : NULL,
                                     json_obj_datum, a_hash_out_type, a_tx_hash, a_chain->net_id, a_version);
    }

    return json_obj_datum;
}

/**
 * @brief Print TX header to JSON
 */
static void s_tx_header_print(dap_json_t *json_obj_datum, dap_chain_tx_hash_processed_ht_t **a_tx_data_ht,
                              dap_chain_datum_tx_t *a_tx, dap_chain_t *a_chain, const char *a_hash_out_type,
                              dap_ledger_t *a_ledger, dap_chain_hash_fast_t *a_tx_hash, dap_chain_hash_fast_t *a_atom_hash,
                              const char *a_token_ticker, int a_ret_code, dap_chain_tx_tag_action_type_t a_action,
                              dap_chain_srv_uid_t a_uid)
{
    bool l_declined = false;
    char l_time_str[DAP_TIME_STR_SIZE] = "unknown";
    if (a_tx->header.ts_created)
        dap_time_to_str_rfc822(l_time_str, DAP_TIME_STR_SIZE, a_tx->header.ts_created);
    
    dap_chain_tx_hash_processed_ht_t *l_tx_data = NULL;
    HASH_FIND(hh, *a_tx_data_ht, a_tx_hash, sizeof(*a_tx_hash), l_tx_data);
    if (l_tx_data) {
        l_declined = true;
    } else {
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
    dap_json_object_add_string(json_obj_datum, "status", l_declined ? "DECLINED" : "ACCEPTED");
    dap_json_object_add_string(json_obj_datum, "hash", l_tx_hash_str);
    dap_json_object_add_string(json_obj_datum, "atom_hash", l_atom_hash_str);
    dap_json_object_add_int(json_obj_datum, "ret_code", a_ret_code);
    dap_json_object_add_string(json_obj_datum, "ret_code_str", dap_ledger_check_error_str(a_ret_code));

    bool srv_found = a_uid.uint64 ? true : false;
    if (srv_found) {
        dap_json_object_add_string(json_obj_datum, "action", dap_ledger_tx_action_str(a_action));
        dap_json_object_add_string(json_obj_datum, "service", dap_ledger_tx_tag_str_by_uid(a_uid));
    } else {
        dap_json_object_add_string(json_obj_datum, "action", "UNKNOWN");
        dap_json_object_add_string(json_obj_datum, "service", "UNKNOWN");
    }

    dap_json_object_add_object(json_obj_datum, "batching", 
        dap_json_object_new_string(!dap_chain_datum_tx_item_get_tsd_by_type(a_tx, DAP_CHAIN_DATUM_TRANSFER_TSD_TYPE_OUT_COUNT) ? "false" : "true"));
    dap_json_object_add_string(json_obj_datum, "tx_created", l_time_str);

    DAP_DELETE(l_tx_hash_str);
    DAP_DELETE(l_atom_hash_str);
}

/**
 * @brief Pack TX history to JSON
 */
static int s_json_tx_history_pack(dap_json_t *a_json_arr_reply, dap_json_t **a_json_obj_datum,
                                  dap_chain_datum_iter_t *a_datum_iter, dap_chain_datum_t *a_datum,
                                  dap_chain_t *a_chain, dap_ledger_t *a_ledger,
                                  dap_chain_tx_tag_action_type_t a_action, const char *a_hash_out_type,
                                  bool a_out_brief, size_t *a_accepted, size_t *a_rejected,
                                  bool a_look_for_unknown_service, const char *a_srv, int a_version)
{
    dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t *)a_datum->data;
    dap_hash_fast_t l_ttx_hash = a_datum_iter->cur_hash ? *a_datum_iter->cur_hash : (dap_hash_fast_t){0};

    const char *service_name = NULL;
    dap_chain_tx_tag_action_type_t l_action = DAP_CHAIN_TX_TAG_ACTION_UNKNOWN;
    l_action = a_datum_iter->action;
    service_name = dap_ledger_tx_action_str(l_action);

    if (!(l_action & a_action))
        return 1;

    if (a_srv) {
        bool srv_found = a_datum_iter->uid.uint64 ? true : false;
        if (a_look_for_unknown_service && srv_found) {
            return 1;
        }
        if (!a_look_for_unknown_service && (!srv_found || strcmp(service_name, a_srv) != 0)) {
            return 1;
        }
    }

    *a_json_obj_datum = s_tx_history_to_json(a_json_arr_reply, &l_ttx_hash, NULL, l_tx, a_chain, a_ledger,
                                              a_hash_out_type, a_datum_iter, a_datum_iter->ret_code, a_out_brief, a_version);
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

/**
 * @brief Get transaction by hash
 */
dap_json_t *dap_db_history_tx(dap_json_t *a_json_arr_reply,
                              dap_chain_hash_fast_t *a_tx_hash,
                              dap_chain_t *a_chain,
                              const char *a_hash_out_type,
                              dap_ledger_t *a_ledger,
                              int a_version)
{
    if (!a_chain->callback_datum_find_by_hash) {
        log_it(L_WARNING, "Not defined callback_datum_find_by_hash for chain \"%s\"", a_chain->name);
        return NULL;
    }

    int l_ret_code = 0;
    dap_hash_fast_t l_atom_hash = {0};
    dap_chain_datum_t *l_datum = a_chain->callback_datum_find_by_hash(a_chain, a_tx_hash, &l_atom_hash, &l_ret_code);
    dap_chain_datum_tx_t *l_tx = l_datum && l_datum->header.type_id == DAP_CHAIN_DATUM_TX ?
                                 (dap_chain_datum_tx_t *)l_datum->data : NULL;

    if (l_tx) {
        return s_tx_history_to_json(a_json_arr_reply, a_tx_hash, &l_atom_hash, l_tx, a_chain, a_ledger,
                                    a_hash_out_type, NULL, l_ret_code, false, a_version);
    } else {
        const char *l_tx_hash_str = dap_strcmp(a_hash_out_type, "hex")
                ? dap_enc_base58_encode_hash_to_str_static(a_tx_hash)
                : dap_chain_hash_fast_to_str_static(a_tx_hash);
        dap_json_rpc_error_add(a_json_arr_reply, -1, "TX hash %s not found in chains", l_tx_hash_str);
        return NULL;
    }
}

/**
 * @brief Get all transactions history
 */
dap_json_t *dap_db_history_tx_all(dap_json_t *a_json_arr_reply, dap_chain_t *a_chain, dap_ledger_t *a_ledger,
                                  const char *a_hash_out_type, dap_json_t *json_obj_summary,
                                  size_t a_limit, size_t a_offset, bool out_brief,
                                  const char *a_srv, dap_chain_tx_tag_action_type_t a_action,
                                  bool a_head, int a_version)
{
    log_it(L_DEBUG, "Start getting tx from chain");
    size_t l_tx_ledger_accepted = 0, l_tx_ledger_rejected = 0, l_count = 0, i_tmp = 0;
    int res = 0;
    dap_json_t *json_arr_out = dap_json_array_new();
    dap_json_t *json_tx_history = NULL;
    size_t l_arr_start = 0, l_arr_end = 0;

    // Get total TX count for proper numbering
    uint64_t l_total_tx_count = a_chain->callback_count_tx(a_chain);

    dap_chain_set_offset_limit_json(json_arr_out, &l_arr_start, &l_arr_end, a_limit, a_offset,
                                     l_total_tx_count, false);

    bool look_for_unknown_service = (a_srv && strcmp(a_srv, "unknown") == 0);
    dap_chain_datum_iter_t *l_datum_iter = a_chain->callback_datum_iter_create(a_chain);

    dap_chain_datum_callback_iters iter_begin = a_head ? a_chain->callback_datum_iter_get_first
                                                        : a_chain->callback_datum_iter_get_last;
    dap_chain_datum_callback_iters iter_direc = a_head ? a_chain->callback_datum_iter_get_next
                                                        : a_chain->callback_datum_iter_get_prev;

    for (dap_chain_datum_t *l_datum = iter_begin(l_datum_iter); l_datum; l_datum = iter_direc(l_datum_iter)) {
        if (i_tmp >= l_arr_end)
            break;
        if (l_datum->header.type_id != DAP_CHAIN_DATUM_TX)
            continue;

        if (i_tmp < l_arr_start) {
            i_tmp++;
            continue;
        }
        res = s_json_tx_history_pack(a_json_arr_reply, &json_tx_history, l_datum_iter, l_datum, a_chain,
                                     a_ledger, a_action, a_hash_out_type, out_brief,
                                     &l_tx_ledger_accepted, &l_tx_ledger_rejected,
                                     look_for_unknown_service, a_srv, a_version);
        if (res == 1)
            continue;
        else if (res == 2) {
            dap_json_object_free(json_arr_out);
            a_chain->callback_datum_iter_delete(l_datum_iter);
            return NULL;
        }
        // Calculate TX number in blockchain:
        // - If iterating from head (oldest first): number = i_tmp + 1 (1, 2, 3, ...)
        // - If iterating from tail (newest first): number = total - i_tmp (35567, 35566, 35565, ...)
        uint64_t l_tx_num = a_head ? (i_tmp + 1) : (l_total_tx_count - i_tmp);
        dap_json_object_add_uint64(json_tx_history, a_version == 1 ? "tx number" : "tx_num", l_tx_num);
        dap_json_array_add(json_arr_out, json_tx_history);
        ++i_tmp;
        l_count++;
    }
    log_it(L_DEBUG, "END getting tx from chain");
    a_chain->callback_datum_iter_delete(l_datum_iter);

    dap_json_object_add_string(json_obj_summary, "network", a_ledger->name);
    dap_json_object_add_string(json_obj_summary, "chain", a_chain->name);
    dap_json_object_add_int(json_obj_summary, "tx_sum", l_count);
    dap_json_object_add_int(json_obj_summary, "accepted_tx", l_tx_ledger_accepted);
    dap_json_object_add_int(json_obj_summary, "rejected_tx", l_tx_ledger_rejected);
    return json_arr_out;
}

/**
 * @brief Get transaction history for address (simplified version)
 */
dap_json_t *dap_db_history_addr(dap_json_t *a_json_arr_reply, dap_chain_addr_t *a_addr, dap_chain_t *a_chain,
                                dap_ledger_t *a_ledger, const char *a_hash_out_type, const char *a_addr_str,
                                dap_json_t *json_obj_summary, size_t a_limit, size_t a_offset,
                                bool a_brief, const char *a_srv, dap_chain_tx_tag_action_type_t a_action,
                                bool a_head, int a_version)
{
    dap_json_t *json_obj_datum = dap_json_array_new();
    if (!json_obj_datum) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        dap_json_rpc_error_add(a_json_arr_reply, -44, "Memory allocation error");
        return NULL;
    }

    // Add address
    dap_json_t *json_obj_addr = dap_json_object_new();
    dap_json_object_add_string(json_obj_addr, a_version == 1 ? "address" : "addr", a_addr_str);
    dap_json_array_add(json_obj_datum, json_obj_addr);

    dap_chain_tx_hash_processed_ht_t *l_tx_data_ht = NULL;
    
    if (!a_chain->callback_datum_iter_create) {
        log_it(L_WARNING, "Not defined callback_datum_iter_create for chain \"%s\"", a_chain->name);
        dap_json_rpc_error_add(a_json_arr_reply, -1, "Not defined callback_datum_iter_create for chain \"%s\"", a_chain->name);
        dap_json_object_free(json_obj_datum);
        return NULL;
    }

    const char *l_native_ticker = a_ledger->native_ticker;
    dap_chain_addr_t l_net_fee_addr = a_ledger->fee_addr;
    bool l_net_fee_used = !IS_ZERO_256(a_ledger->fee_value);
    bool look_for_unknown_service = (a_srv && strcmp(a_srv, "unknown") == 0);

    size_t l_arr_start = 0, l_arr_end = 0;
    dap_chain_set_offset_limit_json(json_obj_datum, &l_arr_start, &l_arr_end, a_limit, a_offset,
                                     a_chain->callback_count_tx(a_chain), false);

    size_t i_tmp = 0, l_count = 0, l_tx_ledger_accepted = 0, l_tx_ledger_rejected = 0;

    dap_chain_datum_iter_t *l_datum_iter = a_chain->callback_datum_iter_create(a_chain);
    dap_chain_datum_callback_iters iter_begin = a_head ? a_chain->callback_datum_iter_get_first
                                                        : a_chain->callback_datum_iter_get_last;
    dap_chain_datum_callback_iters iter_direc = a_head ? a_chain->callback_datum_iter_get_next
                                                        : a_chain->callback_datum_iter_get_prev;

    for (dap_chain_datum_t *l_datum = iter_begin(l_datum_iter); l_datum; l_datum = iter_direc(l_datum_iter)) {
        if (l_datum->header.type_id != DAP_CHAIN_DATUM_TX)
            continue;

        if (i_tmp >= l_arr_end) {
            ++i_tmp;
            continue;
        }

        dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t *)l_datum->data;
        dap_hash_fast_t l_tx_hash = *l_datum_iter->cur_hash;
        const char *l_src_token = l_datum_iter->token_ticker;
        int l_ret_code = l_datum_iter->ret_code;
        uint32_t l_action = l_datum_iter->action;
        dap_hash_fast_t l_atom_hash = *l_datum_iter->cur_atom_hash;
        dap_chain_srv_uid_t l_uid = l_datum_iter->uid;

        // Check if this TX involves our address
        bool l_addr_found = false;
        dap_chain_addr_t *l_src_addr = NULL;

        // Check INs for source address
        uint8_t *l_tx_item = NULL;
        size_t l_size;
        int i;
        TX_ITEM_ITER_TX_TYPE(l_tx_item, TX_ITEM_TYPE_IN_ALL, l_size, i, l_tx) {
            dap_chain_hash_fast_t *l_tx_prev_hash = NULL;
            int l_tx_prev_out_idx;
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
            default:
                continue;
            }

            dap_chain_datum_t *l_datum_prev = l_tx_prev_hash ?
                        a_chain->callback_datum_find_by_hash(a_chain, l_tx_prev_hash, NULL, NULL) : NULL;
            dap_chain_datum_tx_t *l_tx_prev = l_datum_prev && l_datum_prev->header.type_id == DAP_CHAIN_DATUM_TX ?
                                              (dap_chain_datum_tx_t *)l_datum_prev->data : NULL;
            if (l_tx_prev) {
                uint8_t *l_prev_out_union = dap_chain_datum_tx_item_get_nth(l_tx_prev, TX_ITEM_TYPE_OUT_ALL, l_tx_prev_out_idx);
                if (l_prev_out_union) {
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
                    default:
                        break;
                    }
                }
            }
            if (l_src_addr && dap_chain_addr_compare(l_src_addr, a_addr)) {
                l_addr_found = true;
                break;
            }
        }

        // Check OUTs for destination address
        if (!l_addr_found) {
            dap_list_t *l_list_out_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_OUT_ALL, NULL);
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
                    break;
                default:
                    break;
                }
                if (l_dst_addr && dap_chain_addr_compare(l_dst_addr, a_addr)) {
                    l_addr_found = true;
                    break;
                }
            }
            dap_list_free(l_list_out_items);
        }

        if (!l_addr_found)
            continue;

        // Apply filters
        if (!(l_action & a_action))
            continue;

        if (a_srv) {
            bool srv_found = l_uid.uint64 ? true : false;
            const char *l_service_name = dap_ledger_tx_action_str(l_action);
            if (look_for_unknown_service && srv_found)
                continue;
            if (!look_for_unknown_service && (!srv_found || strcmp(l_service_name, a_srv) != 0))
                continue;
        }

        if (i_tmp < l_arr_start) {
            i_tmp++;
            continue;
        }

        // Build TX JSON
        dap_json_t *j_obj_tx = dap_json_object_new();
        s_tx_header_print(j_obj_tx, &l_tx_data_ht, l_tx, a_chain, a_hash_out_type, a_ledger,
                          &l_tx_hash, &l_atom_hash, l_src_token, l_ret_code, l_action, l_uid);

        dap_json_array_add(json_obj_datum, j_obj_tx);
        l_count++;
        i_tmp++;
        l_src_token ? l_tx_ledger_accepted++ : l_tx_ledger_rejected++;
    }

    a_chain->callback_datum_iter_delete(l_datum_iter);
    s_tx_hash_processed_ht_free(&l_tx_data_ht);

    // If no history
    if (dap_json_array_length(json_obj_datum) == 1) {
        dap_json_t *json_empty_tx = dap_json_object_new();
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

/**
 * @brief com_tx_history - Transaction history command
 */
int com_tx_history(int a_argc, char **a_argv, dap_json_t *a_json_arr_reply, int a_version)
{
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

    dap_chain_t *l_chain = NULL;
    dap_ledger_t *l_ledger = NULL;

    const char *l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    if (!l_hash_out_type)
        l_hash_out_type = "hex";
    if (dap_strcmp(l_hash_out_type, "hex") && dap_strcmp(l_hash_out_type, "base58")) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_PARAM_ERR,
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

    dap_chain_tx_tag_action_type_t l_action = l_tx_act_str ? dap_ledger_tx_action_str_to_action_t(l_tx_act_str)
                                                           : DAP_CHAIN_TX_TAG_ACTION_ALL;

    bool l_brief = (dap_cli_server_cmd_check_option(a_argv, arg_index, a_argc, "-brief") != -1) ? true : false;
    bool l_is_tx_all = dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-all", NULL);
    bool l_is_tx_count = dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-count", NULL);

    if (!l_addr_base58 && !l_wallet_name && !l_tx_hash_str && !l_is_tx_all && !l_is_tx_count) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_PARAM_ERR,
                                "tx history requires parameter '-addr' or '-w' or '-tx' or '-all' or '-count'");
        return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_PARAM_ERR;
    }

    if (!l_net_str && !l_addr_base58 && !l_is_tx_all) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_PARAM_ERR,
                                "tx history requires parameter '-net' or '-addr'");
        return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_PARAM_ERR;
    }

    dap_chain_hash_fast_t l_tx_hash;
    if (l_tx_hash_str && dap_chain_hash_fast_from_str(l_tx_hash_str, &l_tx_hash) != 0) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_HASH_REC_ERR, "tx hash not recognized");
        return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_HASH_REC_ERR;
    }

    // Get ledger by net name
    if (l_net_str) {
        l_ledger = dap_ledger_find_by_name(l_net_str);
        if (!l_ledger) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_NET_PARAM_ERR,
                                    "tx history requires parameter '-net' to be valid chain network name");
            return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_NET_PARAM_ERR;
        }
    }

    // Get chain address
    dap_chain_addr_t *l_addr = NULL;
    if (l_addr_base58) {
        if (l_tx_hash_str) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_INCOMPATIBLE_PARAMS_ERR,
                                    "Incompatible params '-addr' & '-tx'");
            return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_INCOMPATIBLE_PARAMS_ERR;
        }
        l_addr = dap_chain_addr_from_str(l_addr_base58);
        if (!l_addr) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_WALLET_ADDR_ERR,
                                    "Wallet address not recognized");
            return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_WALLET_ADDR_ERR;
        }
        if (l_ledger) {
            if (l_ledger->net_id.uint64 != l_addr->net_id.uint64) {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_ID_NET_ADDR_DIF_ERR,
                                        "Network ID with '-net' param and network ID with '-addr' param are different");
                DAP_DELETE(l_addr);
                return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_ID_NET_ADDR_DIF_ERR;
            }
        } else {
            l_ledger = dap_ledger_find_by_net_id(l_addr->net_id);
        }
    }

    if (l_wallet_name) {
        // Check wallet using callback
        if (!l_ledger || !l_ledger->wallet_get_addr_callback) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_WALLET_ERR,
                                    "Wallet callbacks not registered");
            if (l_addr) DAP_DELETE(l_addr);
            return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_WALLET_ERR;
        }
        dap_chain_addr_t *l_addr_tmp = (dap_chain_addr_t *)l_ledger->wallet_get_addr_callback(l_wallet_name, l_ledger->net_id);
        if (!l_addr_tmp) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_WALLET_ERR,
                                    "The wallet %s is not activated or it doesn't exist", l_wallet_name);
            if (l_addr) DAP_DELETE(l_addr);
            return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_WALLET_ERR;
        }
        if (l_addr) {
            if (!dap_chain_addr_compare(l_addr, l_addr_tmp)) {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_ADDR_WALLET_DIF_ERR,
                                        "Address with '-addr' param and address with '-w' param are different");
                DAP_DELETE(l_addr);
                DAP_DELETE(l_addr_tmp);
                return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_ADDR_WALLET_DIF_ERR;
            }
            DAP_DELETE(l_addr_tmp);
        } else {
            l_addr = l_addr_tmp;
        }
    }

    if (!l_ledger) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_NET_ERR,
                                "Could not determine the network for tx history command");
        return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_NET_ERR;
    }

    // Get chain
    if (l_chain_str) {
        dap_chain_info_t *l_chain_info = dap_ledger_get_chain_info_by_name(l_ledger, l_chain_str);
        if (l_chain_info)
            l_chain = (dap_chain_t *)l_chain_info->chain_ptr;
    } else {
        // Find default TX chain
        dap_chain_info_t *l_chain_info = NULL, *l_tmp = NULL;
        HASH_ITER(hh, l_ledger->chains_registry, l_chain_info, l_tmp) {
            if (l_chain_info->chain_type == CHAIN_TYPE_TX) {
                l_chain = (dap_chain_t *)l_chain_info->chain_ptr;
                break;
            }
        }
    }

    if (!l_chain) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_CHAIN_PARAM_ERR,
                                "tx history requires parameter '-chain' to be valid chain name in chain net %s",
                                l_net_str ? l_net_str : "unknown");
        if (l_addr) DAP_DELETE(l_addr);
        return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_CHAIN_PARAM_ERR;
    }

    // Response
    dap_json_t *json_obj_out = NULL;
    if (l_tx_hash_str) {
        // History tx hash
        json_obj_out = dap_db_history_tx(a_json_arr_reply, &l_tx_hash, l_chain, l_hash_out_type, l_ledger, a_version);
        if (!json_obj_out) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_DAP_DB_HISTORY_TX_ERR,
                                    "something went wrong in tx history");
            return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_DAP_DB_HISTORY_TX_ERR;
        }
    } else if (l_addr) {
        // History addr and wallet
        dap_json_t *json_obj_summary = dap_json_object_new();
        if (!json_obj_summary) {
            DAP_DELETE(l_addr);
            return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_MEMORY_ERR;
        }
        json_obj_out = dap_db_history_addr(a_json_arr_reply, l_addr, l_chain, l_ledger, l_hash_out_type,
                                            dap_chain_addr_to_str_static(l_addr), json_obj_summary,
                                            l_limit, l_offset, l_brief, l_tx_srv_str, l_action, l_head, a_version);
        DAP_DELETE(l_addr);
        if (!json_obj_out) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_DAP_DB_HISTORY_ADDR_ERR,
                                    "something went wrong in tx history");
            dap_json_object_free(json_obj_summary);
            return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_DAP_DB_HISTORY_ADDR_ERR;
        }
        dap_json_array_add(a_json_arr_reply, json_obj_out);
        dap_json_array_add(a_json_arr_reply, json_obj_summary);
        return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_OK;
    } else if (l_is_tx_all) {
        // History all
        dap_json_t *json_obj_summary = dap_json_object_new();
        if (!json_obj_summary) {
            return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_MEMORY_ERR;
        }

        dap_json_t *json_arr_history_all = dap_db_history_tx_all(a_json_arr_reply, l_chain, l_ledger, l_hash_out_type,
                                                                  json_obj_summary, l_limit, l_offset, l_brief,
                                                                  l_tx_srv_str, l_action, l_head, a_version);
        if (!json_arr_history_all) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_DAP_DB_HISTORY_ALL_ERR,
                                    "something went wrong in tx history");
            dap_json_object_free(json_obj_summary);
            return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_DAP_DB_HISTORY_ALL_ERR;
        }
        dap_json_array_add(a_json_arr_reply, json_arr_history_all);
        dap_json_array_add(a_json_arr_reply, json_obj_summary);
        return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_OK;
    } else if (l_is_tx_count) {
        dap_json_t *json_count_obj = dap_json_object_new();
        dap_json_object_add_uint64(json_count_obj, "number_of_transaction", l_chain->callback_count_tx(l_chain));
        dap_json_array_add(a_json_arr_reply, json_count_obj);
        return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_OK;
    }

    if (json_obj_out) {
        dap_json_array_add(a_json_arr_reply, json_obj_out);
    } else {
        dap_json_array_add(a_json_arr_reply, dap_json_object_new_string("empty"));
    }

    return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_OK;
}

/**
 * @brief Initialize TX history CLI module
 */
int dap_chain_ledger_cli_tx_history_init(void)
{
    log_it(L_INFO, "TX history CLI module initialized");
    return 0;
}

/**
 * @brief Deinitialize TX history CLI module
 */
void dap_chain_ledger_cli_tx_history_deinit(void)
{
    log_it(L_INFO, "TX history CLI module deinitialized");
}
