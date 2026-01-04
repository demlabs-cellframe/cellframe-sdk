/*
 * Authors:
 * Cellframe       https://cellframe.net
 * DeM Labs Inc.   https://demlabs.net
 * Sources         https://gitlab.demlabs.net/cellframe/cellframe-sdk
 * Copyright  (c) 2017-2025
 * All rights reserved.
 *
 * This file is part of DAP SDK the open source project
 *
 *    DAP SDK is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    DAP SDK is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with any DAP SDK based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <errno.h>
#include <time.h>
#include "dap_common.h"
#include "dap_time.h"
#include "uthash.h"
#include "utlist.h"
#include "dap_string.h"
#include "dap_hash.h"
#include "dap_chain_common.h"
#include "dap_strfuncs.h"
#include "dap_list.h"
#include "dap_cert.h"
#include "dap_file_utils.h"
#include "dap_enc_base58.h"
#include "dap_global_db.h"
#include "dap_chain_mempool_cli.h"
#include "dap_chain_mempool.h"
#include "dap_chain_net_core.h"
#include "dap_cli_server.h"
#include "dap_json_rpc.h"
#include "dap_chain_net.h"
#include "dap_chain_datum.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_ledger.h"
#include "dap_chain_datum_tx_voting.h"
#include "dap_global_db_driver.h"  // For dap_store_obj_t
#include "dap_chain_net_tx.h"      // For dap_chain_tx_datum_from_json

#define LOG_TAG "dap_chain_mempool_cli"

// Forward declarations
static int com_mempool(int a_argc, char **a_argv, dap_json_t *a_json_arr_reply, int a_version);

// Helper function
dap_chain_t *s_get_chain_with_datum(dap_chain_net_t *a_net, const char *a_datum_hash) {
    dap_chain_t *l_chain = NULL;
    DL_FOREACH(a_net->pub.chains, l_chain) {
        char *l_gdb_mempool = dap_chain_mempool_group_new(l_chain);
        bool is_hash = dap_global_db_driver_is(l_gdb_mempool, a_datum_hash);
        DAP_DELETE(l_gdb_mempool);
        if (is_hash)
            return l_chain;
    }
    return NULL;
}

// Mempool list print function
/**
 * @brief s_com_mempool_list_print_for_chain
 *
 * @param a_net
 * @param a_chain
 * @param a_str_tmp
 * @param a_hash_out_type
 */
 void s_com_mempool_list_print_for_chain(dap_json_t *a_json_arr_reply, dap_chain_net_t *a_net, dap_chain_t *a_chain, const char *a_addr,
                                         dap_json_t *a_json_obj, const char *a_hash_out_type, bool a_fast, size_t a_limit, size_t a_offset, int a_version)
{

    dap_chain_addr_t l_wallet_addr = {};
    if (a_addr) {
        dap_chain_addr_t *l_wallet_addr_tmp = dap_chain_addr_from_str(a_addr);
        if (!l_wallet_addr_tmp) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_CMD_VALUE_PARSE_CONVERT_BASE58_TO_ADDR_WALLET, "Cannot convert "
                                                                                                "string '%s' to binary address.\n", a_addr);
            return;
        }
        l_wallet_addr = *l_wallet_addr_tmp;
        DAP_DELETE(l_wallet_addr_tmp);
    }

    if (a_addr && a_fast) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_CMD_VALUE_PARSE_FAST_AND_BASE58_ADDR,
                            "In fast mode, it is impossible to count the number of transactions and emissions "
                            "for a specific address. The -brief and -addr options are mutually exclusive.\n");
        return;
    }
    
    // Создаем основной объект для цепочки и сразу добавляем его в a_json_obj
    dap_json_t *l_obj_chain = dap_json_object_new();
    if (!l_obj_chain) {
        dap_json_rpc_allocation_error(a_json_arr_reply);
        return;
    }
    
    // Добавляем имя цепочки
    dap_json_t *l_obj_chain_name = dap_json_object_new_string(a_chain->name);
    if (!l_obj_chain_name) {
        dap_json_object_free(l_obj_chain);
        dap_json_rpc_allocation_error(a_json_arr_reply);
        return;
    }
    dap_json_object_add_object(l_obj_chain, "name", l_obj_chain_name);
    
    // Фильтрация mempool и добавление информации об удаленных записях
    int l_removed = 0;
    dap_chain_mempool_filter(a_chain, &l_removed);
    
    dap_json_t *l_jobj_removed = dap_json_object_new_int(l_removed);
    if (!l_jobj_removed) {
        dap_json_object_free(l_obj_chain);
        dap_json_rpc_allocation_error(a_json_arr_reply);
        return;
    }
    dap_json_object_add_object(l_obj_chain, "removed", l_jobj_removed);
    
    // Получаем все объекты из mempool
    size_t l_objs_count = 0;
    char * l_gdb_group_mempool = dap_chain_mempool_group_new(a_chain);
    if(!l_gdb_group_mempool) {
        dap_json_rpc_error_add(a_json_arr_reply, -1,  // Generic error code
                            "%s.%s: chain not found\n", a_net->pub.name, a_chain->name);
        return;
    }
    dap_global_db_obj_t * l_objs = dap_global_db_get_all_sync(l_gdb_group_mempool, &l_objs_count);
    DAP_DELETE(l_gdb_group_mempool);    
    // Создаем массив для datums
    dap_json_t *l_jobj_datums = dap_json_array_new();
    if (!l_jobj_datums) {
        dap_global_db_objs_delete(l_objs, l_objs_count);
        dap_json_object_free(l_obj_chain);
        dap_json_rpc_allocation_error(a_json_arr_reply);
        return;
    }
    // Добавляем массив datums в объект chain
    dap_json_object_add_object(l_obj_chain, "datums", l_jobj_datums);
    if (l_objs_count == 0 || l_objs_count < a_offset)
        goto return_obj_chain;
    // Добавление информации о пагинации
    size_t l_arr_start = 0;
    if (a_offset) {
        l_arr_start = a_offset;
        dap_json_t *l_jobj_offset = dap_json_object_new_uint64(a_offset);
        if (!l_jobj_offset) {
            dap_global_db_objs_delete(l_objs, l_objs_count);
            dap_json_object_free(l_obj_chain);
            dap_json_rpc_allocation_error(a_json_arr_reply);
            return;
        }
        dap_json_object_add_object(l_obj_chain, "offset", l_jobj_offset);
    }
    
    size_t l_arr_end = l_objs_count;
    if (a_limit) {
        l_arr_end = a_offset + a_limit;
        if (l_arr_end > l_objs_count)
            l_arr_end = l_objs_count;
        dap_json_t *l_jobj_limit = dap_json_object_new_uint64(l_arr_end);
        if (!l_jobj_limit) {
            dap_global_db_objs_delete(l_objs, l_objs_count);
            dap_json_object_free(l_obj_chain);
            dap_json_rpc_allocation_error(a_json_arr_reply);
            return;
        }
        dap_json_object_add_object(l_obj_chain, "limit", l_jobj_limit);
    }
    
    // Обработка каждого объекта из mempool
    for (size_t i = l_arr_start; i < l_arr_end; i++) {
        dap_chain_datum_t *l_datum = (dap_chain_datum_t *) l_objs[i].value;
        if (!l_datum->header.data_size || (l_datum->header.data_size > l_objs[i].value_len)) {
            log_it(L_ERROR, "Trash datum in GDB %s.%s, key: %s data_size:%u, value_len:%zu",
                    a_net->pub.name, a_chain->name, l_objs[i].key, l_datum->header.data_size, l_objs[i].value_len);
            continue;
        }
        
        // Создаем объект для текущего datum
        dap_json_t *l_jobj_datum = dap_json_object_new();
        if (!l_jobj_datum) {
            dap_global_db_objs_delete(l_objs, l_objs_count);
            dap_json_object_free(l_obj_chain);
            dap_json_rpc_allocation_error(a_json_arr_reply);
            return;
        }
         dap_json_array_add(l_jobj_datums, l_jobj_datum);
        
        // Заполняем информацию о времени создания и хеше
        dap_time_t l_ts_create = (dap_time_t) l_datum->header.ts_create;
        const char *l_datum_type = dap_chain_datum_type_id_to_str(l_datum->header.type_id);
        
        dap_hash_fast_t l_datum_real_hash = {0};
        dap_hash_fast_t l_datum_hash_from_key = {0};
        dap_chain_datum_calc_hash(l_datum, &l_datum_real_hash);
        dap_chain_hash_fast_from_str(l_objs[i].key, &l_datum_hash_from_key);
        
        char buff_time[DAP_TIME_STR_SIZE];
        dap_time_to_str_rfc822(buff_time, DAP_TIME_STR_SIZE, l_datum->header.ts_create);
        
        // Добавляем основную информацию о datum
        // Создаем JSON объекты для типа, хеша и времени создания
        dap_json_t *l_jobj_type = dap_json_object_new_string(l_datum_type);      
        if (!l_jobj_type) {
            dap_json_object_free(l_obj_chain);
            dap_global_db_objs_delete(l_objs, l_objs_count);
            dap_json_rpc_allocation_error(a_json_arr_reply);
            return;
        }
        dap_json_object_add_object(l_jobj_datum, a_version == 1 ? "type" : "datum_type", l_jobj_type);
        dap_json_t *l_jobj_hash = dap_json_object_new_string(l_objs[i].key);
        if (!l_jobj_hash) {
            dap_json_object_free(l_obj_chain);
            dap_global_db_objs_delete(l_objs, l_objs_count);
            dap_json_rpc_allocation_error(a_json_arr_reply);
            return;
        }
        dap_json_object_add_object(l_jobj_datum, a_version == 1 ? "hash" : "datum_hash", l_jobj_hash);
        dap_json_t *l_jobj_ts_created = dap_json_object_new();
        if (!l_jobj_ts_created) {
            dap_json_object_free(l_obj_chain);
            dap_global_db_objs_delete(l_objs, l_objs_count);
            dap_json_rpc_allocation_error(a_json_arr_reply);
            return;
        }
        dap_json_object_add_object(l_jobj_datum, "created", l_jobj_ts_created);
        
        
        dap_json_t *l_jobj_ts_created_time_stamp = dap_json_object_new_uint64(l_ts_create);      
        if (!l_jobj_ts_created_time_stamp) {
            dap_json_object_free(l_obj_chain);
            dap_global_db_objs_delete(l_objs, l_objs_count);
            dap_json_rpc_allocation_error(a_json_arr_reply);
            return;
        }
        dap_json_object_add_object(l_jobj_ts_created, "time_stamp", l_jobj_ts_created_time_stamp);
        dap_json_t *l_jobj_ts_created_str = dap_json_object_new_string(buff_time);
        if (!l_jobj_ts_created_str) {
            dap_json_object_free(l_obj_chain);
            dap_global_db_objs_delete(l_objs, l_objs_count);
            dap_json_rpc_allocation_error(a_json_arr_reply);
            return;
        }
        dap_json_object_add_object(l_jobj_ts_created, "str", l_jobj_ts_created_str);
        
        // Проверяем соответствие хеша и ключа
        if (!dap_hash_fast_compare(&l_datum_real_hash, &l_datum_hash_from_key)) {
            char *l_drh_str = dap_hash_fast_to_str_new(&l_datum_real_hash);
            char *l_wgn = dap_strdup_printf("Key field in DB %s does not match datum's hash %s\n",
                                            l_objs[i].key, l_drh_str);
            DAP_DELETE(l_drh_str);
            
            if (!l_wgn) {
                dap_json_object_free(l_obj_chain);
                dap_global_db_objs_delete(l_objs, l_objs_count);
                dap_json_rpc_allocation_error(a_json_arr_reply);
                return;
            }
            
            dap_json_t *l_jobj_warning = dap_json_object_new_string(l_wgn);
            DAP_DELETE(l_wgn);
            
            if (!l_jobj_warning) {
                dap_json_object_free(l_obj_chain);
                dap_global_db_objs_delete(l_objs, l_objs_count);
                dap_json_rpc_allocation_error(a_json_arr_reply);
                return;
            }
            dap_json_object_add_object(l_jobj_datum, "warning", l_jobj_warning);
            continue;
        }

        if (a_fast) {
            if (a_addr)
                dap_json_array_del_idx(l_jobj_datums, dap_json_array_length(l_jobj_datums) - 1, 1);
            continue;
        }

        // Обработка различных типов datum            
        bool l_datum_is_accepted_addr = false;
        switch (l_datum->header.type_id) {
            case DAP_CHAIN_DATUM_TX: {
                dap_chain_addr_t l_addr_from;
                dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t *) l_datum->data;

                // Получаем информацию из ledger
                int l_ledger_rc = DAP_LEDGER_CHECK_INVALID_ARGS;
                const char *l_main_ticker = dap_ledger_tx_calculate_main_ticker(a_net->pub.ledger, l_tx, &l_ledger_rc);
                const char *l_ledger_rc_str = dap_ledger_check_error_str(l_ledger_rc);

                // Создаем JSON объекты для main_ticker и ledger_rc
                dap_json_t *l_jobj_main_ticker = dap_json_object_new_string(l_main_ticker ? l_main_ticker : "UNKNOWN");
                if (!l_jobj_main_ticker) {
                    dap_json_object_free(l_obj_chain);
                    dap_global_db_objs_delete(l_objs, l_objs_count);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return;
                }
                dap_json_object_add_object(l_jobj_datum, "main_ticker", l_jobj_main_ticker);
                dap_json_t *l_jobj_ledger_rc = dap_json_object_new_string(l_ledger_rc_str);
                if (!l_jobj_ledger_rc) {
                    dap_json_object_free(l_obj_chain);
                    dap_global_db_objs_delete(l_objs, l_objs_count);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return;
                }
                dap_json_object_add_object(l_jobj_datum, "ledger_rc", l_jobj_ledger_rc);

                // Добавляем информацию о сервисе и действии
                dap_chain_srv_uid_t uid;
                char *service_name;
                dap_chain_tx_tag_action_type_t action;
                int l_rc = dap_ledger_deduct_tx_tag(a_net->pub.ledger, l_tx, &service_name, &uid, &action);
                dap_json_t *l_jobj_service = dap_json_object_new_string(l_rc ? service_name : "UNKNOWN");
                if (!l_jobj_service) {
                    dap_json_object_free(l_obj_chain);
                    dap_global_db_objs_delete(l_objs, l_objs_count);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return;
                }
                dap_json_t *l_jobj_action = dap_json_object_new_string(l_rc ? dap_ledger_tx_action_str(action) : "UNKNOWN");
                dap_json_object_add_object(l_jobj_datum, "service", l_jobj_service);
                if (!l_jobj_action) {
                    dap_json_object_free(l_obj_chain);
                    dap_global_db_objs_delete(l_objs, l_objs_count);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return;
                }
                dap_json_object_add_object(l_jobj_datum, "action", l_jobj_action);

                // Добавляем информацию о batching
                dap_json_t *l_jobj_batching = dap_json_object_new_string(
                    !dap_chain_datum_tx_item_get_tsd_by_type(l_tx, DAP_CHAIN_DATUM_TRANSFER_TSD_TYPE_OUT_COUNT) ? "false" : "true");     
                if (!l_jobj_batching) {
                    dap_json_object_free(l_obj_chain);
                    dap_global_db_objs_delete(l_objs, l_objs_count);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return;
                }
                dap_json_object_add_object(l_jobj_datum, "batching", l_jobj_batching);
            
                // Получаем подпись транзакции
                dap_chain_tx_sig_t *l_sig = (dap_chain_tx_sig_t*)dap_chain_datum_tx_item_get(l_tx, NULL, NULL, TX_ITEM_TYPE_SIG, NULL);
                if (!l_sig) {
                    // Обработка ситуации, когда подпись не найдена
                    dap_json_t *l_jobj_wgn = dap_json_object_new_string(
                            "An item with a type TX_ITEM_TYPE_SIG for the "
                            "transaction was not found, the transaction may "
                            "be corrupted.");
                    dap_json_object_add_object(l_jobj_datum, "warning", l_jobj_wgn);
                    continue;
                }
                dap_sign_t *l_sign = dap_chain_datum_tx_item_sig_get_sign(l_sig);
                dap_chain_addr_fill_from_sign(&l_addr_from, l_sign, a_net->pub.id);
                if (a_addr && dap_chain_addr_compare(&l_wallet_addr, &l_addr_from))
                    l_datum_is_accepted_addr = true;

                dap_json_t *l_jobj_to_list = dap_json_array_new();
                if (!l_jobj_to_list) {
                    dap_json_object_free(l_obj_chain);
                    dap_global_db_objs_delete(l_objs, l_objs_count);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return;
                }
                dap_json_object_add_object(l_jobj_datum, "to", l_jobj_to_list);
                dap_json_t *l_jobj_change_list = dap_json_array_new();
                if (!l_jobj_change_list) {
                    dap_json_object_free(l_obj_chain);
                    dap_global_db_objs_delete(l_objs, l_objs_count);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return;
                }
                dap_json_object_add_object(l_jobj_datum, "change", l_jobj_change_list);
                dap_json_t *l_jobj_fee_list = dap_json_array_new();
                if (!l_jobj_fee_list) {
                    dap_json_object_free(l_obj_chain);
                    dap_global_db_objs_delete(l_objs, l_objs_count);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return;
                }
                dap_json_t *l_jobj_to_from_emi = dap_json_array_new();
                if (!l_jobj_to_from_emi) {
                    dap_json_object_free(l_obj_chain);
                    dap_global_db_objs_delete(l_objs, l_objs_count);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return;
                }
                dap_json_object_add_object(l_jobj_datum, "to_from_emi", l_jobj_to_from_emi);
                dap_json_object_add_object(l_jobj_datum, "fee", l_jobj_fee_list);
                dap_json_t *l_jobj_stake_lock_list = dap_json_array_new();
                if (!l_jobj_stake_lock_list) {
                    dap_json_object_free(l_obj_chain);
                    dap_global_db_objs_delete(l_objs, l_objs_count);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return;
                }
                dap_json_object_add_object(l_jobj_datum, "srv_stake_lock", l_jobj_stake_lock_list);
                dap_json_t *l_jobj_xchange_list = dap_json_array_new();
                if (!l_jobj_xchange_list) {
                    dap_json_object_free(l_obj_chain);
                    dap_global_db_objs_delete(l_objs, l_objs_count);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return;
                }
                dap_json_object_add_object(l_jobj_datum, "srv_xchange", l_jobj_xchange_list);
                dap_json_t *l_jobj_stake_pos_delegate_list = dap_json_array_new();
                if (!l_jobj_stake_pos_delegate_list) {
                    dap_json_object_free(l_obj_chain);
                    dap_global_db_objs_delete(l_objs, l_objs_count);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return;
                }
                dap_json_object_add_object(l_jobj_datum, "srv_stake_pos_delegate", l_jobj_stake_pos_delegate_list);
                dap_json_t *l_jobj_emit_delegate_list = dap_json_array_new();
                if (!l_jobj_emit_delegate_list) {
                    dap_json_object_free(l_obj_chain);
                    dap_global_db_objs_delete(l_objs, l_objs_count);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return;
                }
                dap_json_object_add_object(l_jobj_datum, "srv_wallet_shared", l_jobj_emit_delegate_list);
                dap_json_t *l_jobj_stake_ext_lock_list = dap_json_array_new();
                if (!l_jobj_stake_ext_lock_list) {
                    dap_json_object_free(l_obj_chain);
                    dap_global_db_objs_delete(l_objs, l_objs_count);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return;
                }
                dap_json_object_add_object(l_jobj_datum, "srv_stake_ext_lock", l_jobj_stake_ext_lock_list);
                dap_json_t *l_jobj_pay_list = dap_json_array_new();
                if (!l_jobj_pay_list) {
                    dap_json_object_free(l_obj_chain);
                    dap_global_db_objs_delete(l_objs, l_objs_count);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return;
                }
                dap_json_object_add_object(l_jobj_datum, "srv_pay", l_jobj_pay_list);

                enum {
                    OUT_COND_TYPE_UNKNOWN,
                    OUT_COND_TYPE_PAY,
                    OUT_COND_TYPE_FEE,
                    OUT_COND_TYPE_STAKE_LOCK,
                    OUT_COND_TYPE_XCHANGE,
                    OUT_COND_TYPE_POS_DELEGATE,
                    OUT_COND_TYPE_WALLET_SHARED,
                    OUT_COND_TYPE_STAKE_EXT_LOCK
                } l_out_cond_subtype = {0};

                dap_list_t *l_list_in_reward = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_IN_REWARD, NULL);
                if (l_list_in_reward) {
                    /*dap_json_t *l_obj_in_reward_arary = dap_json_array_new();
                    if (!l_obj_in_reward_arary) {
                        dap_list_free(l_list_in_reward);
                        dap_json_object_free(l_jobj_datum);
                        dap_json_object_free(l_jobj_datums);
                        dap_json_object_free(l_obj_chain);
                        dap_global_db_objs_delete(l_objs, l_objs_count);
                        dap_json_rpc_allocation_error(a_json_arr_reply);
                        return;
                    }
                    for (dap_list_t *it = l_list_in_reward; it; it = it->next) {
                        dap_chain_tx_in_reward_t *l_in_reward = (dap_chain_tx_in_reward_t *) it->data;
                        char *l_block_hash = dap_chain_hash_fast_to_str_new(&l_in_reward->block_hash);
                        dap_json_t *l_jobj_block_hash = dap_json_object_new_string(l_block_hash);
                        if (!l_jobj_block_hash) {
                            DAP_DELETE(l_block_hash);
                            dap_json_object_free(l_obj_in_reward_arary);
                            dap_list_free(l_list_in_reward);
                            dap_json_object_free(l_jobj_datum);
                            dap_json_object_free(l_jobj_datums);
                            dap_json_object_free(l_obj_chain);
                            dap_global_db_objs_delete(l_objs, l_objs_count);
                            dap_json_rpc_allocation_error(a_json_arr_reply);
                            return;
                        }
                         dap_json_array_add(l_obj_in_reward_arary, l_jobj_block_hash);
                        DAP_DELETE(l_block_hash);
                    }*/
                    dap_list_free(l_list_in_reward);
                }
                dap_json_t *l_jobj_diff = NULL;
                dap_list_t *l_list_out_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_OUT_ALL, NULL);
                for (dap_list_t *it = l_list_out_items; it; it = it->next) {
                    dap_chain_addr_t *l_dist_addr = NULL;
                    uint256_t l_value = uint256_0;
                    const char *l_dist_token = NULL;
                    uint8_t l_type = *(uint8_t *) it->data;
                    switch (l_type) {
                        case TX_ITEM_TYPE_OUT: {
                            l_value = ((dap_chain_tx_out_t *) it->data)->header.value;
                            l_dist_token = l_main_ticker;
                            l_dist_addr = &((dap_chain_tx_out_t *) it->data)->addr;
                        }
                            break;
                        case TX_ITEM_TYPE_OUT_EXT: {
                            l_value = ((dap_chain_tx_out_ext_t *) it->data)->header.value;
                            l_dist_token = ((dap_chain_tx_out_ext_t *) it->data)->token;
                            l_dist_addr = &((dap_chain_tx_out_ext_t *) it->data)->addr;
                        }
                            break;
                        case TX_ITEM_TYPE_OUT_STD: {
                            l_value = ((dap_chain_tx_out_std_t *) it->data)->value;
                            l_dist_token = ((dap_chain_tx_out_std_t *) it->data)->token;
                            l_dist_addr = &((dap_chain_tx_out_std_t *) it->data)->addr;
                        }
                            break;
                        case TX_ITEM_TYPE_OUT_COND: {
                            dap_chain_tx_out_cond_t *l_out_cond = (dap_chain_tx_out_cond_t *) it->data;
                            l_value = ((dap_chain_tx_out_cond_t *) it->data)->header.value;
                            switch (l_out_cond->header.subtype) {
                                case DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE: {
                                    l_dist_token = a_net->pub.native_ticker;
                                    l_out_cond_subtype = OUT_COND_TYPE_FEE;
                                }
                                    break;
                                case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK: {
                                    l_dist_token = l_main_ticker;
                                    l_out_cond_subtype = OUT_COND_TYPE_STAKE_LOCK;
                                }
                                    break;
                                case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE: {
                                    l_dist_token = l_main_ticker;
                                    l_out_cond_subtype = OUT_COND_TYPE_XCHANGE;
                                }
                                    break;
                                case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE: {
                                    l_dist_token = l_main_ticker;
                                    l_out_cond_subtype = OUT_COND_TYPE_POS_DELEGATE;
                                }
                                    break;
                                case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY: {
                                    l_dist_token = l_main_ticker;
                                    l_out_cond_subtype = OUT_COND_TYPE_PAY;
                                }
                                    break;
                                case DAP_CHAIN_TX_OUT_COND_SUBTYPE_WALLET_SHARED: {
                                    l_dist_token = l_main_ticker;
                                    l_out_cond_subtype = OUT_COND_TYPE_WALLET_SHARED;
                                }
                                    break;
                                default:
                                    break;
                            }
                        }
                            break;
                        default:
                            break;
                    }

                    dap_json_t *l_jobj_money = dap_json_object_new();
                    if (!l_jobj_money) {
                        dap_json_object_free(l_obj_chain);
                        dap_global_db_objs_delete(l_objs, l_objs_count);
                        dap_list_free(l_list_out_items);
                        dap_json_rpc_allocation_error(a_json_arr_reply);
                        return;
                    }
                    const char *l_value_coins_str, *l_value_str = dap_uint256_to_char(l_value, &l_value_coins_str);
                    dap_json_object_add_object(l_jobj_money, "value", dap_json_object_new_string(l_value_str));
                    dap_json_object_add_object(l_jobj_money, "coins", dap_json_object_new_string(l_value_coins_str));

                    if (l_dist_token) {
                        dap_json_t *l_jobj_token = dap_json_object_new_string(l_dist_token);
                        if (!l_jobj_token) {
                            dap_json_object_free(l_jobj_money);
                            dap_json_object_free(l_obj_chain);
                            dap_global_db_objs_delete(l_objs, l_objs_count);
                            dap_list_free(l_list_out_items);
                            dap_json_rpc_allocation_error(a_json_arr_reply);
                            return;
                        }
                        dap_json_object_add_object(l_jobj_money, "token", l_jobj_token);
                    }

                    if (l_dist_addr) {
                        if (!l_datum_is_accepted_addr && a_addr) {
                            l_datum_is_accepted_addr = dap_chain_addr_compare(&l_wallet_addr, l_dist_addr);
                        }
                        dap_json_t *l_jobj_f = dap_json_object_new();
                        if (!l_jobj_f) {
                            dap_json_object_free(l_jobj_money);
                            dap_json_object_free(l_obj_chain);
                            dap_global_db_objs_delete(l_objs, l_objs_count);
                            dap_list_free(l_list_out_items);
                            dap_json_rpc_allocation_error(a_json_arr_reply);
                            return;
                        }
                        dap_json_object_add_object(l_jobj_f, "money", l_jobj_money);
                        if (dap_chain_addr_compare(&l_addr_from, l_dist_addr)) {
                            bool l_in_from_emi = false;
                            // Получаем item типа IN_EMS
                            dap_list_t *l_list_in_ems = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_IN_EMS, NULL);
                            for (dap_list_t *it_ems = l_list_in_ems; it_ems; it_ems = it_ems->next) {
                                dap_chain_tx_in_ems_t *l_in_ems = (dap_chain_tx_in_ems_t *) it_ems->data;
                                if (!dap_strcmp(l_in_ems->header.ticker, l_dist_token)) {
                                    l_in_from_emi = true;
                                    dap_hash_fast_t l_ems_hash = l_in_ems->header.token_emission_hash;
                                    char l_ems_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
                                    dap_hash_fast_to_str(&l_ems_hash, l_ems_hash_str,
                                                            DAP_CHAIN_HASH_FAST_STR_SIZE);
                                    dap_json_t *l_obj_ems_hash = dap_json_object_new_string(l_ems_hash_str);
                                    if (!l_obj_ems_hash) {
                                        dap_json_object_free(l_obj_chain);
                                        dap_json_object_free(l_jobj_f);
                                        dap_global_db_objs_delete(l_objs, l_objs_count);
                                        dap_list_free(l_list_out_items);
                                        dap_json_rpc_allocation_error(a_json_arr_reply);
                                        return;
                                    }
                                    dap_json_object_add_object(l_jobj_f, "token_emission_hash", l_obj_ems_hash);
                                    break;
                                }
                            }
                            if (l_in_from_emi)
                                 dap_json_array_add(l_jobj_to_from_emi, l_jobj_f);
                            else
                                 dap_json_array_add(l_jobj_change_list, l_jobj_f);
                        } else {
                            dap_json_object_add_object(l_jobj_f, "addr", dap_json_object_new_string(dap_chain_addr_to_str_static(l_dist_addr)));
                             dap_json_array_add(l_jobj_to_list, l_jobj_f);
                        }
                    } else {
                        switch (l_out_cond_subtype) {
                            case OUT_COND_TYPE_PAY:
                                 dap_json_array_add(l_jobj_pay_list, l_jobj_money);
                                break;
                            case OUT_COND_TYPE_FEE:
                                 dap_json_array_add(l_jobj_fee_list, l_jobj_money);
                                break;
                            case OUT_COND_TYPE_STAKE_LOCK:
                                 dap_json_array_add(l_jobj_stake_lock_list, l_jobj_money);
                                break;
                            case OUT_COND_TYPE_XCHANGE:
                                 dap_json_array_add(l_jobj_xchange_list, l_jobj_money);
                                break;
                            case OUT_COND_TYPE_POS_DELEGATE:
                                 dap_json_array_add(l_jobj_stake_pos_delegate_list, l_jobj_money);
                                break;
                            case OUT_COND_TYPE_WALLET_SHARED: {
                                dap_json_array_add(l_jobj_emit_delegate_list, l_jobj_money);
                                dap_chain_tx_tsd_t *l_diff_tx_tsd = dap_chain_datum_tx_item_get_tsd_by_type(l_tx, DAP_CHAIN_WALLET_SHARED_TSD_WRITEOFF);
                                if (l_diff_tx_tsd || (l_diff_tx_tsd = dap_chain_datum_tx_item_get_tsd_by_type(l_tx, DAP_CHAIN_WALLET_SHARED_TSD_REFILL))) {
                                    uint256_t l_diff_value = {};
                                    memcpy(&l_diff_value, ((dap_tsd_t *)(l_diff_tx_tsd->tsd))->data, sizeof(uint256_t));
                                    l_value_str = dap_uint256_to_char(l_diff_value, &l_value_coins_str);
                                    l_jobj_diff = dap_json_array_new();
                                    dap_json_t *l_jobj_diff_obj = dap_json_object_new();
                                    dap_json_object_add_object(l_jobj_diff_obj, "value", dap_json_object_new_string(l_value_str));
                                    dap_json_object_add_object(l_jobj_diff_obj, "coins", dap_json_object_new_string(l_value_coins_str));
                                    dap_json_object_add_object(l_jobj_diff_obj, "token", dap_json_object_new_string(l_main_ticker));
                                    dap_json_array_add(l_jobj_diff, l_jobj_diff_obj);
                                }
                                break;
                            }
                            case OUT_COND_TYPE_STAKE_EXT_LOCK:
                                 dap_json_array_add(l_jobj_stake_ext_lock_list, l_jobj_money);
                                break;
                            default:
                                log_it(L_ERROR,
                                        "An unknown subtype output was found in a transaction in the mempool list.");
                                break;
                        }
                    }
                }
                dap_list_free(l_list_out_items);
                dap_json_t *l_jobj_tx_vote = dap_json_array_new();
                if (!l_jobj_tx_vote) {
                    dap_json_object_free(l_obj_chain);
                    dap_global_db_objs_delete(l_objs, l_objs_count);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return;
                }
                dap_json_object_add_object(l_jobj_datum, "vote", l_jobj_tx_vote);
                dap_list_t *l_vote_list = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_VOTE, NULL);
                for (dap_list_t *it = l_vote_list; it; it = it->next) {
                    dap_json_t *l_jobj_vote = dap_chain_datum_tx_item_vote_to_json((dap_chain_tx_vote_t *) it->data, a_version);
                     dap_json_array_add(l_jobj_tx_vote, l_jobj_vote);
                }
                dap_list_free(l_vote_list);

                dap_json_t *l_jobj_tx_voting = dap_json_array_new();
                if (!l_jobj_tx_voting) {
                    dap_json_object_free(l_obj_chain);
                    dap_global_db_objs_delete(l_objs, l_objs_count);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return;
                }
                dap_json_object_add_object(l_jobj_datum, "voting", l_jobj_tx_voting);
                dap_list_t *l_voting_list = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_VOTING, NULL);
                for (dap_list_t *it = l_voting_list; it; it = it->next) {
                    dap_json_t *l_jobj_voting = dap_chain_datum_tx_item_voting_tsd_to_json(l_tx, a_version);
                     dap_json_array_add(l_jobj_tx_voting, l_jobj_voting);
                }
                dap_list_free(l_voting_list);

                dap_json_t *l_jobj_tx_event = dap_json_array_new();
                if (!l_jobj_tx_event) {
                    dap_json_object_free(l_obj_chain);
                    dap_global_db_objs_delete(l_objs, l_objs_count);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return;
                }
                dap_json_object_add_object(l_jobj_datum, "event", l_jobj_tx_event);
                dap_list_t *l_event_list = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_EVENT, NULL);
                for (dap_list_t *it = l_event_list; it; it = it->next) {
                    dap_json_t *l_jobj_event = dap_json_object_new();
                    if (!l_jobj_event) {
                        dap_json_object_free(l_obj_chain);
                        dap_global_db_objs_delete(l_objs, l_objs_count);
                        dap_json_rpc_allocation_error(a_json_arr_reply);
                        return;
                    }
                    int l_ret = dap_chain_datum_tx_item_event_to_json(l_jobj_event, (dap_chain_tx_item_event_t *)it->data);
                    if (l_ret == 0) {
                         dap_json_array_add(l_jobj_tx_event, l_jobj_event);
                    } else {
                        dap_json_object_free(l_jobj_event);
                    }
                }
                dap_list_free(l_event_list);
                if (l_jobj_diff)
                    dap_json_object_add_object(l_jobj_datum, "operation", l_jobj_diff);
                if (!dap_json_array_length(l_jobj_pay_list))
                    dap_json_object_del(l_jobj_datum, "srv_pay");
                if (!dap_json_array_length(l_jobj_xchange_list))
                    dap_json_object_del(l_jobj_datum, "srv_xchange");
                if (!dap_json_array_length(l_jobj_stake_lock_list))
                    dap_json_object_del(l_jobj_datum, "srv_stake_lock");
                if (!dap_json_array_length(l_jobj_stake_pos_delegate_list))
                    dap_json_object_del(l_jobj_datum, "srv_stake_pos_delegate");
                if (!dap_json_array_length(l_jobj_emit_delegate_list))
                    dap_json_object_del(l_jobj_datum, "srv_wallet_shared");
                if (!dap_json_array_length(l_jobj_to_from_emi))
                    dap_json_object_del(l_jobj_datum, "from_emission");
                if (!dap_json_array_length(l_jobj_tx_vote))
                    dap_json_object_del(l_jobj_datum, "vote");
                if (!dap_json_array_length(l_jobj_tx_voting))
                    dap_json_object_del(l_jobj_datum, "voting");
                if (!dap_json_array_length(l_jobj_tx_event))
                    dap_json_object_del(l_jobj_datum, "event");
            }
                break;
            case DAP_CHAIN_DATUM_TOKEN_EMISSION: {
                size_t l_emi_size = l_datum->header.data_size;
                dap_chain_datum_token_emission_t *l_emi = dap_chain_datum_emission_read(l_datum->data,
                                                                                        &l_emi_size);
                if (a_addr && l_emi && dap_chain_addr_compare(&l_wallet_addr, &l_emi->hdr.address))
                    l_datum_is_accepted_addr = true;
                DAP_DELETE(l_emi);
                dap_chain_datum_dump_json(a_json_arr_reply, l_jobj_datum,l_datum,a_hash_out_type,a_net->pub.id, true, a_version);
            }
                break;
            default:
                dap_chain_datum_dump_json(a_json_arr_reply, l_jobj_datum,l_datum,a_hash_out_type,a_net->pub.id, true, a_version);
        }
        if (a_addr && !l_datum_is_accepted_addr)
            dap_json_array_del_idx(l_jobj_datums, dap_json_array_length(l_jobj_datums) - 1, 1);
    }
    // Освобождаем временные ресурсы
    dap_global_db_objs_delete(l_objs, l_objs_count);

    char *l_nets_str = NULL;

return_obj_chain:
    // Добавляем информацию о total
    l_nets_str = dap_strdup_printf("%s.%s: %zu", a_net->pub.name, a_chain->name, l_objs_count);
    dap_json_t *l_object_total = dap_json_object_new_string(l_nets_str);
    DAP_DELETE(l_nets_str);
    
    if (!l_object_total) {
        dap_json_object_free(l_obj_chain);
        dap_json_rpc_allocation_error(a_json_arr_reply);
        return;
    }
    
    // Добавляем total в chain объект
    dap_json_object_add_object(l_obj_chain, "total", l_object_total);
    
    // Добавляем chain в общий массив JSON объектов
     dap_json_array_add(a_json_obj, l_obj_chain);    
}

static int mempool_delete_for_chain(dap_chain_t *a_chain, const char *a_datum_hash_str, dap_json_t *a_json_arr_reply) {
        char * l_gdb_group_mempool = dap_chain_mempool_group_new(a_chain);
        uint8_t *l_data_tmp = dap_global_db_get_sync(l_gdb_group_mempool, a_datum_hash_str,
                                                     NULL, NULL, NULL);
        if (!l_data_tmp) {
            DAP_DELETE(l_gdb_group_mempool);
            return 1;
        }
        if (dap_global_db_del_sync(l_gdb_group_mempool, a_datum_hash_str) == 0) {
            DAP_DELETE(l_gdb_group_mempool);
            DAP_DELETE(l_data_tmp);
            return 0;
        } else {
            DAP_DELETE(l_gdb_group_mempool);
            DAP_DELETE(l_data_tmp);
            return 2;
        }
}

typedef enum cmd_mempool_delete_err_list{
    COM_MEMPOOL_DELETE_ERR_DATUM_NOT_FOUND_IN_ARGUMENT = DAP_JSON_RPC_ERR_CODE_METHOD_ERR_START,
    COM_MEMPOOL_DELETE_ERR_DATUM_NOT_FOUND
}cmd_mempool_delete_err_list_t;
/**
 * @brief _cmd_mempool_delete
 * @param argc
 * @param argv
 * @param arg_func
 * @param a_json_arr_reply
 * @return
 */
int _cmd_mempool_delete(dap_chain_net_t *a_net, dap_chain_t *a_chain, const char *a_datum_hash, dap_json_t *a_json_arr_reply, int a_version)
{
    if (!a_net || !a_datum_hash) {
        dap_json_rpc_error_add(a_json_arr_reply, COM_MEMPOOL_DELETE_ERR_DATUM_NOT_FOUND_IN_ARGUMENT, "Net or datum hash not specified");
        return COM_MEMPOOL_DELETE_ERR_DATUM_NOT_FOUND_IN_ARGUMENT;
    }
    int res = 0;
    dap_json_t *l_jobj_ret = dap_json_object_new();
    dap_json_t *l_jobj_net = dap_json_object_new_string(a_net->pub.name);
    dap_json_t *l_jobj_chain = NULL;
    dap_json_t *l_jobj_datum_hash = dap_json_object_new_string(a_datum_hash);
    if (!a_chain) {
        dap_chain_t * l_chain = s_get_chain_with_datum(a_net, a_datum_hash);
        if (l_chain) {
            res = mempool_delete_for_chain(l_chain, a_datum_hash, a_json_arr_reply);
            l_jobj_chain = dap_json_object_new_string(l_chain->name);
        } else {
            res = 1;
            l_jobj_chain = dap_json_object_new_string("empty chain parameter");
        }
    } else {
        res = mempool_delete_for_chain(a_chain, a_datum_hash, a_json_arr_reply);
        l_jobj_chain = dap_json_object_new_string(a_chain->name);
    }
    dap_json_object_add_object(l_jobj_ret, "net", l_jobj_net);
    dap_json_object_add_object(l_jobj_ret, "chain", l_jobj_chain);
    dap_json_object_add_object(l_jobj_ret, a_version == 1 ? "hash" : "datum_hash", l_jobj_datum_hash);
    dap_json_object_add_string(l_jobj_ret, "action", "delete");
    dap_json_t *l_jobj_ret_code = dap_json_object_new_int(res);
    dap_json_object_add_object(l_jobj_ret, a_version == 1 ? "retCode" : "ret_code", l_jobj_ret_code);
    dap_json_t *l_jobj_status = NULL;
    if (!res) {
        l_jobj_status = dap_json_object_new_string("deleted");
    } else if (res == 1) {
        l_jobj_status = dap_json_object_new_string("datum not found");
    } else {
        l_jobj_status = dap_json_object_new_string("datum was found but could not be deleted");
    }
    dap_json_object_add_object(l_jobj_ret, "status", l_jobj_status);
    dap_json_array_add(a_json_arr_reply, l_jobj_ret);
    if (res) {
        return COM_MEMPOOL_DELETE_ERR_DATUM_NOT_FOUND;
    }
    return 0;
}

/**
 * @brief s_com_mempool_check_datum_in_chain
 * @param a_chain
 * @param a_datum_hash_str
 * @return finded store object or NULL
 */
static dap_store_obj_t *s_com_mempool_check_datum_in_chain(dap_chain_t *a_chain, const char *a_datum_hash_str)
{
    dap_return_val_if_fail(a_datum_hash_str, NULL);
    char *l_gdb_group_mempool = dap_chain_mempool_group_new(a_chain);
    return dap_global_db_get_raw_sync(l_gdb_group_mempool, a_datum_hash_str);
}

typedef enum cmd_mempool_check_err_list {
    COM_MEMPOOL_CHECK_ERR_CAN_NOT_FIND_CHAIN = DAP_JSON_RPC_ERR_CODE_METHOD_ERR_START,
    COM_MEMPOOL_CHECK_ERR_CAN_NOT_FIND_NET,
    COM_MEMPOOL_CHECK_ERR_REQUIRES_DATUM_HASH,
    COM_MEMPOOL_CHECK_ERR_INCORRECT_HASH_STR,
    COM_MEMPOOL_CHECK_ERR_DATUM_NOT_FIND,
    COM_MEMPOOL_CHECK_ERR_VALUE_NOT_FIND
}cmd_mempool_check_err_list_t;

/**
 * @brief _cmd_mempool_check
 * @param a_net
 * @param a_chain
 * @param a_datum_hash
 * @param a_hash_out_type
 * @param a_json_arr_reply
 * @return int
 */
int _cmd_mempool_check(dap_chain_net_t *a_net, dap_chain_t *a_chain, const char *a_datum_hash, const char *a_hash_out_type, dap_json_t *a_json_arr_reply, int a_version)
{
    if (!a_net || !a_datum_hash) {
        dap_json_rpc_error_add(a_json_arr_reply, COM_MEMPOOL_CHECK_ERR_CAN_NOT_FIND_NET, "Error! Both -net <network_name> "
                                                                       "and -datum <data_hash> parameters are required.");
        return COM_MEMPOOL_CHECK_ERR_CAN_NOT_FIND_NET;
    }
    dap_chain_datum_t *l_datum = NULL;
    char *l_chain_name = a_chain ? a_chain->name : NULL;
    bool l_found_in_chains = false;
    int l_ret_code = 0;
    dap_hash_fast_t l_atom_hash = {};
    // FIND in chain
    {
        //
        dap_hash_fast_t l_datum_hash;
        if (dap_chain_hash_fast_from_hex_str(a_datum_hash, &l_datum_hash)) {
            dap_json_rpc_error_add(a_json_arr_reply, COM_MEMPOOL_CHECK_ERR_INCORRECT_HASH_STR,
                                    "Incorrect hash string %s", a_datum_hash);
            return COM_MEMPOOL_CHECK_ERR_INCORRECT_HASH_STR;
        }
        if (a_chain)
            l_datum = a_chain->callback_datum_find_by_hash(a_chain, &l_datum_hash, &l_atom_hash, &l_ret_code);
        else {
            dap_chain_t *it = NULL;
            DL_FOREACH(a_net->pub.chains, it) {
                l_datum = it->callback_datum_find_by_hash(it, &l_datum_hash, &l_atom_hash, &l_ret_code);
                if (l_datum) {
                    l_chain_name = it->name;
                    break;
                }
            }
        }
        if (l_datum)
            l_found_in_chains = true;
    }
    //  FIND in mempool
    bool l_hole = false;
    if (!l_found_in_chains) {
        dap_store_obj_t *l_store_obj = NULL;
        if (a_chain) {
            l_store_obj = s_com_mempool_check_datum_in_chain(a_chain, a_datum_hash);
        } else {
            dap_chain_t *it = NULL;
            DL_FOREACH(a_net->pub.chains, it) {
                l_store_obj = s_com_mempool_check_datum_in_chain(it, a_datum_hash);
                if (l_store_obj) {
                    l_chain_name = it->name;
                    break;
                }
            }
        }
        if (l_store_obj && l_store_obj->value) {
            l_hole = DAP_FLAG_CHECK(l_store_obj->flags, DAP_GLOBAL_DB_RECORD_DEL);
            if (l_hole) {
                l_ret_code = strtol((const char *)l_store_obj->value, NULL, 10);
            } else {
                l_datum = DAP_DUP_SIZE(l_store_obj->value, l_store_obj->value_len);
            }
            dap_store_obj_free_one(l_store_obj);
        }
    }
    dap_json_t *l_jobj_datum = dap_json_object_new();
    dap_json_t *l_datum_hash = dap_json_object_new_string(a_datum_hash);
    dap_json_t *l_net_obj = dap_json_object_new_string(a_net->pub.name);
    if (!l_jobj_datum || !l_datum_hash || !l_net_obj){
        dap_json_object_free(l_jobj_datum);
        dap_json_object_free(l_datum_hash);
        dap_json_object_free(l_net_obj);
        dap_json_rpc_allocation_error(a_json_arr_reply);
        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
    }
    dap_json_t *l_chain_obj;
    if(l_chain_name) {
        l_chain_obj = dap_json_object_new_string(l_chain_name);
        if (!l_chain_obj) {
            dap_json_object_free(l_jobj_datum);
            dap_json_object_free(l_datum_hash);
            dap_json_object_free(l_net_obj);
            dap_json_rpc_allocation_error(a_json_arr_reply);
            return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
        }
    } else
        l_chain_obj = dap_json_object_new();
    dap_json_object_add_object(l_jobj_datum, a_version == 1 ? "hash" : "datum_hash", l_datum_hash);
    dap_json_object_add_object(l_jobj_datum, "net", l_net_obj);
    dap_json_object_add_object(l_jobj_datum, "chain", l_chain_obj);
    dap_json_t *l_find_bool;
    if (l_datum || l_hole) {
        l_find_bool = dap_json_object_new_bool(TRUE);
        dap_json_t *l_find_chain_or_mempool = dap_json_object_new_string(l_found_in_chains ? "chain" : "mempool");
        if (!l_find_chain_or_mempool || !l_find_bool) {
            dap_json_object_free(l_find_chain_or_mempool);
            dap_json_object_free(l_find_bool);
            dap_json_object_free(l_jobj_datum);
            dap_json_rpc_allocation_error(a_json_arr_reply);
            return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
        }
        dap_json_object_add_object(l_jobj_datum, "find", l_find_bool);
        dap_json_object_add_object(l_jobj_datum, "source", l_find_chain_or_mempool);
        if (l_found_in_chains) {
            char l_atom_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
            dap_chain_hash_fast_to_str(&l_atom_hash, l_atom_hash_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
            dap_json_t *l_obj_atom = dap_json_object_new();
            dap_json_t *l_jobj_atom_hash = dap_json_object_new_string(l_atom_hash_str);
            dap_json_t *l_jobj_atom_err = dap_json_object_new_string(dap_ledger_check_error_str(l_ret_code));
            if (!l_obj_atom || !l_jobj_atom_hash || !l_jobj_atom_err) {
                dap_json_object_free(l_jobj_datum);
                dap_json_object_free(l_obj_atom);
                dap_json_object_free(l_jobj_atom_hash);
                dap_json_object_free(l_jobj_atom_err);
                dap_json_rpc_allocation_error(a_json_arr_reply);
                return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
            }
            dap_json_object_add_object(l_obj_atom, a_version == 1 ? "hash" : "atom_hash", l_jobj_atom_hash);
            dap_json_object_add_object(l_obj_atom, "ledger_response_code", l_jobj_atom_err);
            dap_json_object_add_object(l_jobj_datum, "atom", l_obj_atom);
        }
        if (l_hole) {
            dap_json_object_add_object(l_jobj_datum, "status", dap_json_object_new_string("hole"));
            dap_json_object_add_object(l_jobj_datum, "ledger_response_code", dap_json_object_new_string(dap_ledger_check_error_str(l_ret_code)));
            dap_json_array_add(a_json_arr_reply, l_jobj_datum);
            return 0;
        }
        dap_json_t *l_datum_obj_inf = dap_json_object_new();
        dap_chain_datum_dump_json(a_json_arr_reply, l_datum_obj_inf, l_datum, a_hash_out_type, a_net->pub.id, true, a_version);
        if (!l_datum_obj_inf) {
            if (!l_found_in_chains)
                DAP_DELETE(l_datum);
            dap_json_object_free(l_jobj_datum);
            dap_json_rpc_error_add(a_json_arr_reply, DAP_JSON_RPC_ERR_CODE_SERIALIZATION_DATUM_TO_JSON,
                                    "Failed to serialize datum to JSON.");
            return DAP_JSON_RPC_ERR_CODE_SERIALIZATION_DATUM_TO_JSON;
        }
        dap_json_object_add_object(l_jobj_datum, "datum", l_datum_obj_inf);
        if (!l_found_in_chains)
            DAP_DELETE(l_datum);
        dap_json_array_add(a_json_arr_reply, l_jobj_datum);
        return 0;
    } else {
        l_find_bool = dap_json_object_new_bool(FALSE);
        if (!l_find_bool) {
            dap_json_object_free(l_jobj_datum);
            dap_json_rpc_allocation_error(a_json_arr_reply);
            return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
        }
        dap_json_object_add_object(l_jobj_datum, "find", l_find_bool);
        dap_json_array_add(a_json_arr_reply, l_jobj_datum);
        return COM_MEMPOOL_CHECK_ERR_DATUM_NOT_FIND;
    }
}

typedef enum cmd_mempool_proc_list_error{
    DAP_COM_MEMPOOL_PROC_LIST_ERROR_NODE_ROLE_NOT_FULL = DAP_JSON_RPC_ERR_CODE_METHOD_ERR_START,
    DAP_COM_MEMPOOL_PROC_LIST_ERROR_GET_DATUM_HASH_FROM_STR,
    DAP_COM_MEMPOOL_PROC_LIST_ERROR_DATUM_CORRUPT_SIZE_DATUM_NOT_EQUALS_SIZE_RECORD,
    DAP_COM_MEMPOOL_PROC_LIST_ERROR_CAN_NOT_GROUP_NAME,
    DAP_COM_MEMPOOL_PROC_LIST_ERROR_CAN_NOT_FIND_DATUM,
    DAP_COM_MEMPOOL_PROC_LIST_ERROR_CAN_NOT_CONVERT_DATUM_HASH_TO_DIGITAL_FORM,
    DAP_COM_MEMPOOL_PROC_LIST_ERROR_REAL_HASH_DATUM_DOES_NOT_MATCH_HASH_DATA_STRING,
    DAP_COM_MEMPOOL_PROC_LIST_ERROR_FALSE_VERIFY,
    DAP_COM_MEMPOOL_PROC_LIST_ERROR_CAN_NOT_MOVE_TO_NO_CONCENSUS_FROM_MEMPOOL

}cmd_mempool_proc_list_error_t;

/**
 * @brief _cmd_mempool_proc
 * process mempool datum
 * @param a_net
 * @param a_chain
 * @param a_datum_hash
 * @param a_json_arr_reply
 * @return

int _cmd_mempool_proc(dap_chain_net_t *a_net, dap_chain_t *a_chain, const char *a_datum_hash, dap_json_t *a_json_arr_reply, int a_version)
{
    // If full or light it doesnt work
    if(dap_chain_net_get_role(a_net).enums>= NODE_ROLE_FULL){
        dap_json_rpc_error_add(a_json_arr_reply, DAP_COM_MEMPOOL_PROC_LIST_ERROR_NODE_ROLE_NOT_FULL,
                               "Need master node role or higher for network %s to process this command", a_net->pub.name);
        return DAP_COM_MEMPOOL_PROC_LIST_ERROR_NODE_ROLE_NOT_FULL;
    }
    dap_chain_t *l_chain = !a_chain ? s_get_chain_with_datum(a_net, a_datum_hash) : a_chain;

    int ret = 0;
    char *l_gdb_group_mempool = dap_chain_mempool_group_new(l_chain);
    if (!l_gdb_group_mempool){
        dap_json_rpc_error_add(a_json_arr_reply, DAP_COM_MEMPOOL_PROC_LIST_ERROR_CAN_NOT_GROUP_NAME,
                               "Failed to get mempool group name on network %s", a_net->pub.name);
        return DAP_COM_MEMPOOL_PROC_LIST_ERROR_CAN_NOT_GROUP_NAME;
    }
    size_t l_datum_size=0;

    dap_chain_datum_t * l_datum = (dap_chain_datum_t*)dap_global_db_get_sync(l_gdb_group_mempool, a_datum_hash,
                                                                             &l_datum_size, NULL, NULL );
    size_t l_datum_size2 = l_datum? dap_chain_datum_size( l_datum): 0;
    if (l_datum_size != l_datum_size2) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_COM_MEMPOOL_PROC_LIST_ERROR_DATUM_CORRUPT_SIZE_DATUM_NOT_EQUALS_SIZE_RECORD, "Error! Corrupted datum %s, size by datum headers is %zd when in mempool is only %zd bytes",
                                            a_datum_hash, l_datum_size2, l_datum_size);
        DAP_DELETE(l_gdb_group_mempool);
        return DAP_COM_MEMPOOL_PROC_LIST_ERROR_DATUM_CORRUPT_SIZE_DATUM_NOT_EQUALS_SIZE_RECORD;
    }
    if (!l_datum) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_COM_MEMPOOL_PROC_LIST_ERROR_CAN_NOT_FIND_DATUM,
                               "Error! Can't find datum %s", a_datum_hash);
        DAP_DELETE(l_gdb_group_mempool);
        return DAP_COM_MEMPOOL_PROC_LIST_ERROR_CAN_NOT_FIND_DATUM;
    }
    dap_hash_fast_t l_datum_hash, l_real_hash;
    if (dap_chain_hash_fast_from_hex_str(a_datum_hash, &l_datum_hash)) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_COM_MEMPOOL_PROC_LIST_ERROR_CAN_NOT_CONVERT_DATUM_HASH_TO_DIGITAL_FORM,
                               "Error! Can't convert datum hash string %s to digital form",
                               a_datum_hash);
        DAP_DELETE(l_gdb_group_mempool);
        return DAP_COM_MEMPOOL_PROC_LIST_ERROR_CAN_NOT_CONVERT_DATUM_HASH_TO_DIGITAL_FORM;
    }
    dap_chain_datum_calc_hash(l_datum, &l_real_hash);
    if (!dap_hash_fast_compare(&l_datum_hash, &l_real_hash)) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_COM_MEMPOOL_PROC_LIST_ERROR_REAL_HASH_DATUM_DOES_NOT_MATCH_HASH_DATA_STRING,
                               "Error! Datum's real hash doesn't match datum's hash string %s",
                               a_datum_hash);
        DAP_DELETE(l_gdb_group_mempool);
        return DAP_COM_MEMPOOL_PROC_LIST_ERROR_REAL_HASH_DATUM_DOES_NOT_MATCH_HASH_DATA_STRING;
    }
    char buf[DAP_TIME_STR_SIZE];
    dap_time_t l_ts_create = (dap_time_t)l_datum->header.ts_create;
    const char *l_type = NULL;
    DAP_DATUM_TYPE_STR(l_datum->header.type_id, l_type);
    dap_json_t *l_jobj_res = dap_json_object_new();
    dap_json_t *l_jobj_datum = dap_json_object_new();
    dap_json_t *l_jobj_hash = dap_json_object_new_string(a_datum_hash);
    dap_json_t *l_jobj_type = dap_json_object_new_string(l_type);
    dap_json_t *l_jobj_ts_created = dap_json_object_new();
    dap_json_t *l_jobj_ts_created_time_stamp = dap_json_object_new_uint64(l_ts_create);
    int l_res = dap_time_to_str_rfc822(buf, DAP_TIME_STR_SIZE, l_ts_create);
    if (l_res < 0 || !l_jobj_ts_created || !l_jobj_ts_created_time_stamp || !l_jobj_type ||
        !l_jobj_hash || !l_jobj_datum || !l_jobj_res) {
        dap_json_object_free(l_jobj_res);
        dap_json_object_free(l_jobj_datum);
        dap_json_object_free(l_jobj_hash);
        dap_json_object_free(l_jobj_type);
        dap_json_object_free(l_jobj_ts_created);
        dap_json_object_free(l_jobj_ts_created_time_stamp);
        dap_json_rpc_allocation_error(a_json_arr_reply);
        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
    }
    dap_json_t *l_jobj_ts_created_str = dap_json_object_new_string(buf);
    dap_json_t *l_jobj_data_size = dap_json_object_new_uint64(l_datum->header.data_size);
    if (!l_jobj_ts_created_str || !l_jobj_data_size) {
        dap_json_object_free(l_jobj_res);
        dap_json_object_free(l_jobj_datum);
        dap_json_object_free(l_jobj_hash);
        dap_json_object_free(l_jobj_type);
        dap_json_object_free(l_jobj_ts_created);
        dap_json_object_free(l_jobj_ts_created_time_stamp);
        dap_json_object_free(l_jobj_ts_created_str);
        dap_json_object_free(l_jobj_data_size);
        dap_json_rpc_allocation_error(a_json_arr_reply);
        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
    }
    dap_json_object_add_object(l_jobj_datum, a_version == 1 ? "hash" : "datum_hash", l_jobj_hash);
    dap_json_object_add_object(l_jobj_datum, a_version == 1 ? "type" : "datum_type", l_jobj_type);
    dap_json_object_add_object(l_jobj_ts_created, "time_stamp", l_jobj_ts_created_time_stamp);
    dap_json_object_add_object(l_jobj_ts_created, "str", l_jobj_ts_created_str);
    dap_json_object_add_object(l_jobj_datum, "ts_created", l_jobj_ts_created);
    dap_json_object_add_object(l_jobj_datum, "data_size", l_jobj_data_size);
    dap_json_object_add_object(l_jobj_res, "datum", l_jobj_datum);
    dap_json_t *l_jobj_verify = dap_json_object_new();
    if (!l_jobj_verify) {
        dap_json_object_free(l_jobj_res);
        dap_json_rpc_allocation_error(a_json_arr_reply);
        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
    }
    int l_verify_datum = dap_chain_net_verify_datum_for_add(l_chain, l_datum, &l_datum_hash);
    if (l_verify_datum){
        dap_json_t *l_jobj_verify_err = dap_json_object_new_string(dap_chain_net_verify_datum_err_code_to_str(l_datum, l_verify_datum));
        dap_json_t *l_jobj_verify_status = dap_json_object_new_bool(FALSE);
        if (!l_jobj_verify_status || !l_jobj_verify_err) {
            dap_json_object_free(l_jobj_verify_status);
            dap_json_object_free(l_jobj_verify_err);
            dap_json_object_free(l_jobj_verify);
            dap_json_object_free(l_jobj_res);
            dap_json_rpc_allocation_error(a_json_arr_reply);
            return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
        }
        dap_json_object_add_object(l_jobj_verify, a_version == 1 ? "isProcessed" : "processed", l_jobj_verify_status);
        dap_json_object_add_object(l_jobj_verify, "error", l_jobj_verify_err);
        ret = DAP_COM_MEMPOOL_PROC_LIST_ERROR_FALSE_VERIFY;
    } else {
        if (l_chain->callback_add_datums) {
            if (l_chain->callback_add_datums(l_chain, &l_datum, 1) == 0) {
                dap_json_t *l_jobj_verify_status = dap_json_object_new_bool(FALSE);
                if (!l_jobj_verify_status) {
                    dap_json_object_free(l_jobj_verify_status);
                    dap_json_object_free(l_jobj_verify);
                    dap_json_object_free(l_jobj_res);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_verify, a_version == 1 ? "isProcessed" : "processed", l_jobj_verify_status);
                ret = DAP_COM_MEMPOOL_PROC_LIST_ERROR_FALSE_VERIFY;
            } else {
                dap_json_t *l_jobj_verify_status = dap_json_object_new_bool(TRUE);
                if (!l_jobj_verify_status) {
                    dap_json_object_free(l_jobj_verify);
                    dap_json_object_free(l_jobj_res);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_verify, a_version == 1 ? "isProcessed" : "processed", l_jobj_verify_status);
                if (false) { //dap_global_db_del_sync(l_gdb_group_mempool, a_datum_hash)){
                    dap_json_t *l_jobj_wrn_text = dap_json_object_new_string("Can't delete datum from mempool!");
                    if (!l_jobj_wrn_text) {
                        dap_json_object_free(l_jobj_verify);
                        dap_json_object_free(l_jobj_res);
                        dap_json_rpc_allocation_error(a_json_arr_reply);
                        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                    }
                    dap_json_object_add_object(l_jobj_verify, "warning", l_jobj_wrn_text);
                } else {
                    dap_json_t *l_jobj_text = dap_json_object_new_string("Removed datum from mempool.");
                    if (!l_jobj_text) {
                        dap_json_object_free(l_jobj_verify);
                        dap_json_object_free(l_jobj_res);
                        dap_json_rpc_allocation_error(a_json_arr_reply);
                        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                    }
                    dap_json_object_add_object(l_jobj_verify, "notice", l_jobj_text);
                }
            }
        } else {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_COM_MEMPOOL_PROC_LIST_ERROR_CAN_NOT_MOVE_TO_NO_CONCENSUS_FROM_MEMPOOL, "Error! Can't move to no-concensus chains from mempool");
            ret = DAP_COM_MEMPOOL_PROC_LIST_ERROR_CAN_NOT_MOVE_TO_NO_CONCENSUS_FROM_MEMPOOL;
        }
    }
    DAP_DELETE(l_gdb_group_mempool);
    dap_json_object_add_object(l_jobj_res, "verify", l_jobj_verify);
    dap_json_array_add(a_json_arr_reply, l_jobj_res);
    return ret;
}


/**
 * @breif _cmd_mempool_proc_all
 * @param a_net
 * @param a_chain
 * @param a_json_arr_reply
 * @return

int _cmd_mempool_proc_all(dap_chain_net_t *a_net, dap_chain_t *a_chain, dap_json_t *a_json_arr_reply)
{
    if (!a_net || !a_chain) {
        dap_json_rpc_error_add(a_json_arr_reply, -2, "The net and chain argument is not set");
        return -2;
    }

    dap_json_t *l_ret = dap_json_object_new();
    if (!l_ret){
        dap_json_rpc_allocation_error(a_json_arr_reply);
        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
    }
    if(!dap_chain_net_by_id(a_chain->net_id)) {
        char *l_warn_str = dap_strdup_printf("%s.%s: chain not found\n", a_net->pub.name,
                                             a_chain->name);
        if (!l_warn_str) {
            dap_json_object_free(l_ret);
            dap_json_rpc_allocation_error(a_json_arr_reply);
            return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
        }
        dap_json_t *l_warn_obj = dap_json_object_new_string(l_warn_str);
        DAP_DELETE(l_warn_str);
        if (!l_warn_obj){
            dap_json_object_free(l_ret);
            dap_json_rpc_allocation_error(a_json_arr_reply);
            return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
        }
        dap_json_object_add_object(l_ret, "warning", l_warn_obj);
    }

   dap_chain_node_mempool_process_all(a_chain, true);
    char *l_str_result = dap_strdup_printf("The entire mempool has been processed in %s.%s.",
                                           a_net->pub.name, a_chain->name);
    if (!l_str_result) {
        dap_json_object_free(l_ret);
        dap_json_rpc_allocation_error(a_json_arr_reply);
        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
    }
    dap_json_t *l_obj_result = dap_json_object_new_string(l_str_result);
    DAP_DEL_Z(l_str_result);
    if (!l_obj_result) {
        dap_json_object_free(l_ret);
        dap_json_rpc_allocation_error(a_json_arr_reply);
        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
    }
    dap_json_object_add_object(l_ret, "result", l_obj_result);
    dap_json_array_add(a_json_arr_reply, l_obj_result);
    return 0;
}

typedef enum _cmd_mempool_dump_error_list{
    COM_DUMP_ERROR_LIST_CORRUPTED_SIZE = DAP_JSON_RPC_ERR_CODE_METHOD_ERR_START,
    COM_DUMP_ERROR_CAN_NOT_FIND_DATUM,
    COM_DUMP_ERROR_NULL_IS_ARGUMENT_FUNCTION
}_cmd_mempool_dump_error_list_t;

int _cmd_mempool_dump_from_group(dap_chain_net_id_t a_net_id, const char *a_group_gdb, const char *a_datum_hash,
                                 const char *a_hash_out_type, dap_json_t *a_json_arr_reply, int a_version, bool a_tx_to_json)
{
    size_t l_datum_size = 0;
    dap_chain_datum_t *l_datum = (dap_chain_datum_t *)dap_global_db_get_sync(a_group_gdb, a_datum_hash,
                                                         &l_datum_size, NULL, NULL );
    size_t l_datum_size2 = l_datum? dap_chain_datum_size( l_datum): 0;
    if (l_datum_size != l_datum_size2) {
        dap_json_rpc_error_add(a_json_arr_reply, COM_DUMP_ERROR_LIST_CORRUPTED_SIZE, "Error! Corrupted datum %s, size by datum headers "
                                                                   "is %zd when in mempool is only %zd bytes",
                                 a_datum_hash, l_datum_size2, l_datum_size);
        return COM_DUMP_ERROR_LIST_CORRUPTED_SIZE;
    }
    if (!l_datum) {
        dap_json_rpc_error_add(a_json_arr_reply, COM_DUMP_ERROR_LIST_CORRUPTED_SIZE, "Error! Can't find datum %s in %s", a_datum_hash, a_group_gdb);
        return COM_DUMP_ERROR_CAN_NOT_FIND_DATUM;
    }

    dap_json_t *l_jobj_datum = dap_json_object_new();
    if (a_tx_to_json && l_datum->header.type_id == DAP_CHAIN_DATUM_TX) {
        dap_chain_net_tx_to_json((dap_chain_datum_tx_t *)l_datum->data, l_jobj_datum);
    } else {
        dap_chain_datum_dump_json(a_json_arr_reply, l_jobj_datum, l_datum, a_hash_out_type, a_net_id, true, a_version);
    }
    dap_json_array_add(a_json_arr_reply, l_jobj_datum);
    return 0;
}

int _cmd_mempool_dump(dap_chain_net_t *a_net, dap_chain_t *a_chain, const char *a_datum_hash, const char *a_hash_out_type, dap_json_t *a_json_arr_reply, int a_version, bool a_tx_to_json)
{
    if (!a_net || !a_datum_hash || !a_hash_out_type) {
        dap_json_rpc_error_add(a_json_arr_reply, COM_DUMP_ERROR_NULL_IS_ARGUMENT_FUNCTION, "The following arguments are not set: network,"
                                                                         " datum hash, and output hash type. "
                                                                         "Functions required for operation.");
        return COM_DUMP_ERROR_NULL_IS_ARGUMENT_FUNCTION;
    }
    if (a_chain) {
        char *l_group_mempool = dap_chain_mempool_group_new(a_chain);
        _cmd_mempool_dump_from_group(a_net->pub.id, l_group_mempool, a_datum_hash, a_hash_out_type, a_json_arr_reply, a_version, a_tx_to_json);
        DAP_DELETE(l_group_mempool);
    } else {
        dap_chain_t *l_chain = NULL;
        DL_FOREACH(a_net->pub.chains, l_chain){
            char *l_group_mempool = dap_chain_mempool_group_new(l_chain);
            if (!_cmd_mempool_dump_from_group(a_net->pub.id, l_group_mempool, a_datum_hash, a_hash_out_type, a_json_arr_reply, a_version, a_tx_to_json)){
                DAP_DELETE(l_group_mempool);
                break;
            }
            DAP_DELETE(l_group_mempool);
        }
    }
    return 0;
}

int com_mempool(int a_argc, char **a_argv, dap_json_t *a_json_arr_reply, int a_version)
{
    int arg_index = 1;
    dap_chain_net_t *l_net = NULL;
    dap_chain_t *l_chain = NULL;
    enum _subcmd {SUBCMD_LIST, SUBCMD_PROC, SUBCMD_PROC_ALL, SUBCMD_DELETE, SUBCMD_ADD_CA, SUBCMD_CHECK, SUBCMD_DUMP,
            SUBCMD_COUNT};
    enum _subcmd l_cmd = 0;
    if (a_argv[1]) {
        if (!dap_strcmp(a_argv[1], "list")) {
            l_cmd = SUBCMD_LIST;
        } else if (!dap_strcmp(a_argv[1], "proc")) {
            l_cmd = SUBCMD_PROC;
        } else if (!dap_strcmp(a_argv[1], "proc_all")) {
            l_cmd = SUBCMD_PROC_ALL;
        } else if (!dap_strcmp(a_argv[1], "delete")) {
            l_cmd = SUBCMD_DELETE;
        } else if (!dap_strcmp(a_argv[1], "add_ca")) {
            l_cmd = SUBCMD_ADD_CA;
        } else if (!dap_strcmp(a_argv[1], "dump")) {
            l_cmd = SUBCMD_DUMP;
        } else if (!dap_strcmp(a_argv[1], "check")) {
            l_cmd = SUBCMD_CHECK;
        } else if (!dap_strcmp(a_argv[1], "count")) {
            l_cmd = SUBCMD_COUNT;
        } else {
            char *l_str_err = dap_strdup_printf("Invalid sub command specified. Sub command %s "
                                                           "is not supported.", a_argv[1]);
            if (!l_str_err) {
                dap_json_rpc_allocation_error(a_json_arr_reply);
                return -1;
            }
            dap_json_t *l_jobj_str_err = dap_json_object_new_string(l_str_err);
            DAP_DELETE(l_str_err);
            if (!l_jobj_str_err) {
                dap_json_rpc_allocation_error(a_json_arr_reply);
                return -1;
            }
            dap_json_array_add(a_json_arr_reply, l_jobj_str_err);
            return -2;
        }
    }
    int cmd_parse_status = dap_chain_net_parse_net_chain(a_json_arr_reply, &arg_index, a_argc, a_argv, &l_chain, &l_net, CHAIN_TYPE_INVALID);
    if (cmd_parse_status != 0){
        dap_json_rpc_error_add(a_json_arr_reply, cmd_parse_status, "Request parsing error (code: %d)", cmd_parse_status);
            return cmd_parse_status;
    }
    const char *l_hash_out_type = "hex";
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    const char *l_datum_hash_in = NULL;
    char *l_datum_hash = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-datum", &l_datum_hash_in);
    if (l_datum_hash_in) {
        if(dap_strncmp(l_datum_hash_in, "0x", 2) && dap_strncmp(l_datum_hash_in, "0X", 2)) {
            l_datum_hash = dap_enc_base58_to_hex_str_from_str(l_datum_hash_in);
        } else
            l_datum_hash = dap_strdup(l_datum_hash_in);
        if (!l_datum_hash) {
            dap_json_rpc_error_add(a_json_arr_reply, -4, "Can't convert hash string %s to hex string", l_datum_hash_in);
            return -4;
        }
    }
    int ret = -100;
    switch (l_cmd) {
        case SUBCMD_LIST: {
            if (!l_net) {
                dap_json_rpc_error_add(a_json_arr_reply, -5, "The command does not include the net parameter. Please specify the "
                                           "parameter something like this mempool list -net <net_name>");
                return -5;
            }
            dap_json_t *obj_ret = dap_json_object_new();
            dap_json_t *obj_net = dap_json_object_new_string(l_net->pub.name);
            if (!obj_ret || !obj_net) {
                dap_json_object_free(obj_ret);
                dap_json_object_free(obj_net);
                dap_json_rpc_allocation_error(a_json_arr_reply);
                return -1;
            }
            dap_json_object_add_object(obj_ret, "net", obj_net);
            const char *l_wallet_addr = NULL;
            if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-addr", &l_wallet_addr) && !l_wallet_addr) {
                dap_json_t *l_jobj_err = dap_json_object_new_string("Parameter '-addr' require <addr>");
                if (!l_jobj_err) {
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return -1;
                }
                dap_json_array_add(a_json_arr_reply, l_jobj_err);
                return -3;
            }
            dap_json_t *l_jobj_chains = dap_json_array_new();
            if (!l_jobj_chains) {
                dap_json_object_free(obj_ret);
                dap_json_rpc_allocation_error(a_json_arr_reply);
                return -1;
            }
            bool l_fast = (dap_cli_server_cmd_check_option(a_argv, arg_index, a_argc, "-brief") != -1) ? true : false;
            size_t l_limit = 0, l_offset = 0;
            const char *l_limit_str = NULL, *l_offset_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-limit", &l_limit_str);
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-offset", &l_offset_str);
            l_limit = l_limit_str ? strtoul(l_limit_str, NULL, 10) : 1000;
            l_offset = l_offset_str ? strtoul(l_offset_str, NULL, 10) : 0;
            if(l_chain) {
                s_com_mempool_list_print_for_chain(a_json_arr_reply, l_net, l_chain, l_wallet_addr, l_jobj_chains, l_hash_out_type, l_fast, l_limit, l_offset, a_version);
            } else {
                DL_FOREACH(l_net->pub.chains, l_chain) {
                    s_com_mempool_list_print_for_chain(a_json_arr_reply, l_net, l_chain, l_wallet_addr, l_jobj_chains, l_hash_out_type, l_fast, l_limit, l_offset, a_version);
                }
            }
            dap_json_object_add_object(obj_ret, "chains", l_jobj_chains);
            dap_json_array_add(a_json_arr_reply, obj_ret);
            ret = 0;
        } break;
        case SUBCMD_PROC: {
            ret = _cmd_mempool_proc(l_net, l_chain, l_datum_hash, a_json_arr_reply, a_version);
        } break;
        case SUBCMD_PROC_ALL: {
            ret = _cmd_mempool_proc_all(l_net, l_chain, a_json_arr_reply);
        } break;
        case SUBCMD_DELETE: {
            if (l_datum_hash) {
                ret = _cmd_mempool_delete(l_net, l_chain, l_datum_hash, a_json_arr_reply, a_version);
            } else {
                dap_json_rpc_error_add(a_json_arr_reply, -3, "Error! %s requires -datum <datum hash> option", a_argv[0]);
                ret = -3;
            }
        } break;
        case SUBCMD_ADD_CA: {
            const char *l_ca_name  = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-ca_name", &l_ca_name);
            if (!l_ca_name) {
                dap_json_rpc_error_add(a_json_arr_reply, -3, "mempool add_ca requires parameter '-ca_name' to specify the certificate name");
                ret = -3;
            }
            dap_cert_t *l_cert = dap_cert_find_by_name(l_ca_name);
            if (!l_cert) {
                dap_json_rpc_error_add(a_json_arr_reply, -4, "Cert with name '%s' not found.", l_ca_name);
                ret = -4;
            }
            ret = _cmd_mempool_add_ca(l_net, l_chain, l_cert, a_json_arr_reply);
            DAP_DELETE(l_cert);
        } break;
        case SUBCMD_CHECK: {
            ret = _cmd_mempool_check(l_net, l_chain, l_datum_hash, l_hash_out_type, a_json_arr_reply, a_version);
        } break;
        case SUBCMD_DUMP: {
            if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-tx_to_json", NULL)) {
                ret = _cmd_mempool_dump(l_net, l_chain, l_datum_hash, l_hash_out_type, a_json_arr_reply, a_version, true);
            } else {
                ret = _cmd_mempool_dump(l_net, l_chain, l_datum_hash, l_hash_out_type, a_json_arr_reply, a_version, false);
            }
        } break;
        case SUBCMD_COUNT: {
            char *l_mempool_group;
            dap_json_t *obj_ret = dap_json_object_new();
            dap_json_t *obj_net = dap_json_object_new_string(l_net->pub.name);
            if (!obj_ret || !obj_net) {
                dap_json_object_free(obj_ret);
                dap_json_object_free(obj_net);
                dap_json_rpc_allocation_error(a_json_arr_reply);
                return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
            }
            dap_json_object_add_object(obj_ret, "net", obj_net);
            dap_json_t *l_jobj_chains = dap_json_array_new();
            if (!l_jobj_chains) {
                dap_json_object_free(obj_ret);
                dap_json_rpc_allocation_error(a_json_arr_reply);
                return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
            }
            if(l_chain) {
                l_mempool_group = dap_chain_mempool_group_new(l_chain);
                size_t l_objs_count = 0;
                dap_global_db_obj_t *l_objs = dap_global_db_get_all_sync(l_mempool_group, &l_objs_count);
                dap_global_db_objs_delete(l_objs, l_objs_count);
                DAP_DELETE(l_mempool_group);
                dap_json_t *l_jobj_chain = dap_json_object_new();
                dap_json_t *l_jobj_chain_name = dap_json_object_new_string(l_chain->name);
                dap_json_t *l_jobj_count = dap_json_object_new_uint64(l_objs_count);
                if (!l_jobj_chain || !l_jobj_chain_name || !l_jobj_count) {
                    dap_json_object_free(l_jobj_chains);
                    dap_json_object_free(l_jobj_chain);
                    dap_json_object_free(l_jobj_chain_name);
                    dap_json_object_free(l_jobj_count);
                    dap_json_object_free(obj_ret);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_chain, "name", l_jobj_chain_name);
                dap_json_object_add_object(l_jobj_chain, "count", l_jobj_count);
                dap_json_array_add(l_jobj_chains, l_jobj_chain);
            } else {
                DL_FOREACH(l_net->pub.chains, l_chain) {
                    l_mempool_group = dap_chain_mempool_group_new(l_chain);
                    size_t l_objs_count = 0;
                    dap_global_db_obj_t *l_objs = dap_global_db_get_all_sync(l_mempool_group, &l_objs_count);
                    dap_global_db_objs_delete(l_objs, l_objs_count);
                    DAP_DELETE(l_mempool_group);
                    dap_json_t *l_jobj_chain = dap_json_object_new();
                    dap_json_t *l_jobj_chain_name = dap_json_object_new_string(l_chain->name);
                    dap_json_t *l_jobj_count = dap_json_object_new_uint64(l_objs_count);
                    if (!l_jobj_chain || !l_jobj_chain_name || !l_jobj_count) {
                        dap_json_object_free(l_jobj_chains);
                        dap_json_object_free(l_jobj_chain);
                        dap_json_object_free(l_jobj_chain_name);
                        dap_json_object_free(l_jobj_count);
                        dap_json_object_free(obj_ret);
                        dap_json_rpc_allocation_error(a_json_arr_reply);
                        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                    }
                    dap_json_object_add_object(l_jobj_chain, "name", l_jobj_chain_name);
                    dap_json_object_add_object(l_jobj_chain, "count", l_jobj_count);
                    dap_json_array_add(l_jobj_chains, l_jobj_chain);
                }
            }
            dap_json_object_add_object(obj_ret, "chains", l_jobj_chains);
            dap_json_array_add(a_json_arr_reply, obj_ret);
            ret = 0;
        } break;
    }
    DAP_DEL_Z(l_datum_hash);
    return ret;
}

int _cmd_mempool_add_ca(dap_chain_net_t *a_net, dap_chain_t *a_chain, dap_cert_t *a_cert, dap_json_t *a_json_arr_reply)
{
    if (!a_net || !a_chain || !a_cert){
        dap_json_rpc_error_add(a_json_arr_reply, COM_MEMPOOL_ADD_CA_ERROR_NET_NOT_FOUND, "The network or certificate attribute was not passed.");
        return COM_MEMPOOL_ADD_CA_ERROR_NET_NOT_FOUND;
    }
    dap_chain_t *l_chain = NULL;
    // Chech for chain if was set or not
    if (!a_chain){
       // If wasn't set - trying to auto detect
        l_chain = dap_chain_net_get_chain_by_chain_type(a_net, CHAIN_TYPE_CA);
        if (!l_chain) { // If can't auto detect
            // clean previous error code
            dap_json_rpc_error_add(a_json_arr_reply, COM_MEMPOOL_ADD_CA_ERROR_NO_CAINS_FOR_CA_DATUM_IN_NET,
                                   "No chains for CA datum in network \"%s\"", a_net->pub.name);
            return COM_MEMPOOL_ADD_CA_ERROR_NO_CAINS_FOR_CA_DATUM_IN_NET;
        }
    }
    if(!a_cert->enc_key){
        dap_json_rpc_error_add(a_json_arr_reply, COM_MEMPOOL_ADD_CA_ERROR_CORRUPTED_CERTIFICATE_WITHOUT_KEYS,
                               "Corrupted certificate \"%s\" without keys certificate", a_cert->name);
        return COM_MEMPOOL_ADD_CA_ERROR_CORRUPTED_CERTIFICATE_WITHOUT_KEYS;
    }

    if (a_cert->enc_key->priv_key_data_size || a_cert->enc_key->priv_key_data){
        dap_json_rpc_error_add(a_json_arr_reply, COM_MEMPOOL_ADD_CA_ERROR_CERTIFICATE_HAS_PRIVATE_KEY_DATA,
                               "Certificate \"%s\" has private key data. Please export public only key certificate without private keys", a_cert->name);
        return COM_MEMPOOL_ADD_CA_ERROR_CERTIFICATE_HAS_PRIVATE_KEY_DATA;
    }

    // Serialize certificate into memory
    uint32_t l_cert_serialized_size = 0;
    byte_t * l_cert_serialized = dap_cert_mem_save(a_cert, &l_cert_serialized_size);
    if(!l_cert_serialized){
        dap_json_rpc_error_add(a_json_arr_reply, COM_MEMPOOL_ADD_CA_ERROR_CAN_NOT_SERIALIZE,
                               "Can't serialize in memory certificate \"%s\"", a_cert->name);
        return COM_MEMPOOL_ADD_CA_ERROR_CAN_NOT_SERIALIZE;
    }
    // Now all the chechs passed, forming datum for mempool
    dap_chain_datum_t * l_datum = dap_chain_datum_create( DAP_CHAIN_DATUM_CA, l_cert_serialized , l_cert_serialized_size);
    DAP_DELETE( l_cert_serialized);
    if(!l_datum){
        dap_json_rpc_error_add(a_json_arr_reply, COM_MEMPOOL_ADD_CA_ERROR_CAN_NOT_SERIALIZE,
                               "Can't produce datum from certificate \"%s\"", a_cert->name);
        return COM_MEMPOOL_ADD_CA_ERROR_CAN_NOT_SERIALIZE;
    }

    // Finaly add datum to mempool
    char *l_hash_str = dap_chain_mempool_datum_add(l_datum, l_chain, "hex");
    DAP_DELETE(l_datum);
    if (l_hash_str) {
        char *l_msg = dap_strdup_printf("Datum %s was successfully placed to mempool", l_hash_str);
        if (!l_msg) {
            dap_json_rpc_allocation_error(a_json_arr_reply);
            return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
        }
        dap_json_t *l_obj_message = dap_json_object_new_string(l_msg);
        DAP_DELETE(l_msg);
        DAP_DELETE(l_hash_str);
        if (!l_obj_message) {
            dap_json_rpc_allocation_error(a_json_arr_reply);
            return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
        }
        dap_json_array_add(a_json_arr_reply, l_obj_message);
        return 0;
    } else {
        char *l_msg = dap_strdup_printf("Can't place certificate \"%s\" to mempool", a_cert->name);
        if (!l_msg) {
            dap_json_rpc_allocation_error(a_json_arr_reply);
            return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
        }
        dap_json_t *l_obj_msg = dap_json_object_new_string(l_msg);
        DAP_DELETE(l_msg);
        if (!l_obj_msg) {
            dap_json_rpc_allocation_error(a_json_arr_reply);
            return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
        }
        dap_json_array_add(a_json_arr_reply, l_obj_msg);
        return COM_MEMPOOL_ADD_CA_ERROR_CAN_NOT_PLACE_CERTIFICATE;
    }
}

/**
 * @brief com_chain_ca_copy
 * @details copy public CA into the mempool
 * @param a_argc
 * @param a_argv
 * @param a_arg_func
 * @param a_json_arr_reply
 */

/**
 * @brief Create transaction from json file and add to mempool
 * Moved from ledger CLI - this is mempool operation
 * @param a_argc
 * @param a_argv
 * @param a_json_arr_reply
 * @param a_version
 * @return int
 */
int com_mempool_add(int a_argc, char ** a_argv, dap_json_t *a_json_arr_reply, int a_version)
{
    UNUSED(a_version);
    int l_arg_index = 1;
    const char *l_net_name = NULL;
    const char *l_chain_name = NULL;
    const char *l_json_file_path = NULL;
    const char *l_json_str = NULL;

    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_name);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-chain", &l_chain_name);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-json", &l_json_file_path);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-tx_obj", &l_json_str);

    if(!l_json_file_path && !l_json_str) {
        dap_json_rpc_error_add(a_json_arr_reply, -1,
                               "Command requires one of parameters '-json <json file path> or -tx_obj <string>'");
        return -1;
    } 

    // Open json file
    dap_json_t *l_json = NULL;
    if (l_json_file_path){
        l_json = dap_json_from_file(l_json_file_path);
        if(!l_json) {
            dap_json_rpc_error_add(a_json_arr_reply, -1,
                                "Can't open json file");
            return -1;
        }
    } else if (l_json_str) {
        l_json = dap_json_parse_string(l_json_str);
        if(!l_json) {
            dap_json_rpc_error_add(a_json_arr_reply, -1,
                                "Can't parse input JSON-string");
            return -1;
        }
    }
    if(!dap_json_is_object(l_json)) {
        dap_json_rpc_error_add(a_json_arr_reply, -1, "Wrong json format");
        dap_json_object_free(l_json);
        return -1;
    }

    // Read network from json file
    if(!l_net_name) {
        dap_json_t *l_json_net = NULL;
        dap_json_object_get_ex(l_json, "net", &l_json_net);
        if(l_json_net && dap_json_is_string(l_json_net)) {
            l_net_name = dap_json_get_string(l_json_net);
        }
        if(!l_net_name) {
            dap_json_rpc_error_add(a_json_arr_reply, -1,
                                   "Command requires parameter '-net' or set net in the json file");
            dap_json_object_free(l_json);
            return -1;
        }
    }
    dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_name);
    if(!l_net) {
        dap_json_rpc_error_add(a_json_arr_reply, -1, "Not found net by name");
        dap_json_object_free(l_json);
        return -1;
    }
    
    // Read chain from json file
    if(!l_chain_name) {
        dap_json_t *l_json_chain = NULL;
        dap_json_object_get_ex(l_json, "chain", &l_json_chain);
        if(l_json_chain && dap_json_is_string(l_json_chain)) {
            l_chain_name = dap_json_get_string(l_json_chain);
        }
    }
    dap_chain_t *l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_name);
    if(!l_chain) {
        l_chain = dap_chain_net_get_chain_by_chain_type(l_net, CHAIN_TYPE_TX);
    }
    if(!l_chain) {
        dap_json_rpc_error_add(a_json_arr_reply, -1,
                               "Chain not found");
        dap_json_object_free(l_json);
        return -1;
    }
    
    dap_json_t *l_jobj_arr_errors = dap_json_array_new();
    size_t l_items_ready = 0, l_items_count = 0;
    dap_chain_datum_tx_t *l_tx = NULL;
    int l_ret = dap_chain_tx_datum_from_json(l_json, l_net, l_jobj_arr_errors, &l_tx, &l_items_count, &l_items_ready);

    dap_json_t *l_jobj_ret = dap_json_object_new();

    if(l_items_ready < l_items_count || l_ret) {
        dap_json_t *l_tx_create = dap_json_object_new_bool(false);
        dap_json_t *l_jobj_valid_items = dap_json_object_new_uint64(l_items_ready);
        dap_json_t *l_jobj_total_items = dap_json_object_new_uint64(l_items_count);
        dap_json_object_add_object(l_jobj_ret, "tx_create", l_tx_create);
        dap_json_object_add_object(l_jobj_ret, "valid_items", l_jobj_valid_items);
        dap_json_object_add_object(l_jobj_ret, "total_items", l_jobj_total_items);
        dap_json_object_add_object(l_jobj_ret, "errors", l_jobj_arr_errors);

        if (l_tx) DAP_DELETE(l_tx);
        if (l_ret)
            dap_json_rpc_error_add(a_json_arr_reply, l_ret,
                                   "Can't create transaction from json file");
        dap_json_array_add(a_json_arr_reply, l_jobj_ret);
        return -1;
    }
    dap_json_object_free(l_jobj_arr_errors);

    // Pack transaction into the datum
    dap_chain_datum_t *l_datum_tx = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, dap_chain_datum_tx_get_size(l_tx));
    size_t l_datum_tx_size = dap_chain_datum_size(l_datum_tx);
    if (l_tx) DAP_DELETE(l_tx);

    // Add transaction to mempool
    char *l_gdb_group_mempool = dap_chain_mempool_group_new(l_chain);
    char *l_tx_hash_str = dap_get_data_hash_str(l_datum_tx->data, l_datum_tx->header.data_size).s;
    bool l_placed = !dap_global_db_set(l_gdb_group_mempool, l_tx_hash_str, l_datum_tx, l_datum_tx_size, false, NULL, NULL);

    DAP_DEL_Z(l_datum_tx);
    DAP_DELETE(l_gdb_group_mempool);
    if(!l_placed) {
        dap_json_rpc_error_add(a_json_arr_reply, -1,
                               "Can't add transaction to mempool");
        return -1;
    }
    // Completed successfully
    dap_json_t *l_jobj_tx_create = dap_json_object_new_bool(true);
    dap_json_t *l_jobj_hash = dap_json_object_new_string(l_tx_hash_str);
    dap_json_t *l_jobj_total_items = dap_json_object_new_uint64(l_items_ready);
    dap_json_object_add_object(l_jobj_ret, "tx_create", l_jobj_tx_create);
    dap_json_object_add_object(l_jobj_ret, "hash", l_jobj_hash);
    dap_json_object_add_object(l_jobj_ret, "total_items", l_jobj_total_items);
    dap_json_array_add(a_json_arr_reply, l_jobj_ret);
    return 0;
}

/**
 * @brief Initialize mempool CLI commands
 * 
 * Registers all mempool-related commands with the CLI server.
 * 
 * @return 0 on success, negative error code on failure
 */
int dap_chain_mempool_cli_init(void)
{
    // Register mempool command
    // Signature: dap_cli_server_cmd_add(name, callback, json_callback, doc, id, doc_ex)
    const char *l_doc = "mempool { list | proc | proc_all | delete | add_ca | check | dump | count | add }\n"
                        "Manage mempool operations\n"
                        "\nExamples:\n"
                        "  mempool list -net main -chain main\n"
                        "  mempool proc -net main -datum 0x123...\n"
                        "  mempool delete -net main -datum 0x123...\n"
                        "  mempool add -net main -json /path/to/tx.json\n";
    dap_cli_server_cmd_add("mempool", com_mempool, NULL, "Mempool operations", 0, l_doc);
    
    // Register mempool_add as separate command for backwards compatibility
    const char *l_doc_add = "mempool_add -net <net_name> [-chain <chain_name>] { -json <file> | -tx_obj <json_string> }\n"
                            "Add transaction from JSON to mempool\n"
                            "\nExamples:\n"
                            "  mempool_add -net main -json /path/to/tx.json\n"
                            "  mempool_add -net main -tx_obj '{\"version\":1,...}'\n";
    dap_cli_server_cmd_add("mempool_add", com_mempool_add, NULL, "Add TX from JSON to mempool", 0, l_doc_add);

    log_it(L_INFO, "Mempool CLI commands registered");
    return 0;
}

/**
 * @brief Cleanup mempool CLI
 */
void dap_chain_mempool_cli_deinit(void)
{
    log_it(L_INFO, "Mempool CLI commands unregistered");
}
