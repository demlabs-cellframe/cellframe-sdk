/*
* Authors:
* Pavel Uhanov <pavel.uhanov@demlabs.net>
* Cellframe       https://cellframe.net
* DeM Labs Inc.   https://demlabs.net
* Copyright  (c) 2017-2025
* All rights reserved.

This file is part of CellFrame SDK the open source project

CellFrame SDK is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

CellFrame SDK is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "dap_chain_policy.h"
#include "dap_chain_net.h"
#include "dap_chain_datum_decree.h"
#include "dap_list.h"
#include "uthash.h"

#define LOG_TAG "dap_chain_policy"

typedef struct dap_chain_net dap_chain_net_t;

struct policy_net_list_item {
    uint64_t net_id;
    uint32_t last_num_policy;
    dap_list_t *exception_list;
    dap_list_t *policies;
};

static dap_list_t *s_net_list = NULL;

/**
 * @brief search net element in list by id
 * @param a_net_id
 * @return pointer if find, NULL if not
 */
DAP_STATIC_INLINE struct policy_net_list_item *s_net_find(uint64_t a_net_id)
{
    for (dap_list_t *l_iter = dap_list_first(s_net_list); l_iter; l_iter = l_iter->next) {
        if ( ((struct policy_net_list_item *)(l_iter->data))->net_id == a_net_id)
            return (struct policy_net_list_item *)(l_iter->data);
    }
    return NULL;
}

DAP_STATIC_INLINE int s_policy_num_compare(dap_list_t  *a_list1, dap_list_t  *a_list2)
{
    return ((dap_chain_policy_t *)(a_list1->data))->activate.num == ((dap_chain_policy_t *)(a_list2->data))->activate.num ? 0 :
        ((dap_chain_policy_t *)(a_list1->data))->activate.num > ((dap_chain_policy_t *)(a_list2->data))->activate.num ? 1 : -1;
}

static dap_chain_datum_decree_t *s_decree_policy_execute(dap_chain_net_t *a_net, dap_cert_t *a_cert, dap_chain_policy_t *a_policy)
{
    dap_return_val_if_pass(!a_net || !a_cert || !a_policy, NULL);
    // create updating decree
    size_t l_total_tsd_size = sizeof(dap_tsd_t) + dap_chain_policy_get_size(a_policy);

    dap_chain_datum_decree_t *l_decree = DAP_NEW_Z_SIZE(dap_chain_datum_decree_t, sizeof(dap_chain_datum_decree_t) + l_total_tsd_size);
    if (!l_decree) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    l_decree->decree_version = DAP_CHAIN_DATUM_DECREE_VERSION;
    l_decree->header.ts_created = dap_time_now();
    l_decree->header.type = DAP_CHAIN_DATUM_DECREE_TYPE_COMMON;
    l_decree->header.common_decree_params.net_id = a_net->pub.id;
    dap_chain_t *l_chain = dap_chain_net_get_default_chain_by_chain_type(a_net, CHAIN_TYPE_ANCHOR);
    if (!l_chain)
        l_chain =  dap_chain_net_get_chain_by_chain_type(a_net, CHAIN_TYPE_ANCHOR);
    if (!l_chain) {
        log_it(L_ERROR, "No chain supported anchor datum type");
        DAP_DEL_Z(l_decree);
        return NULL;
    }
    l_decree->header.common_decree_params.chain_id = l_chain->id;
    l_decree->header.common_decree_params.cell_id = *dap_chain_net_get_cur_cell(a_net);
    l_decree->header.sub_type = DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_PKEY_UPDATE;
    l_decree->header.data_size = l_total_tsd_size;
    l_decree->header.signs_size = 0;
    dap_tsd_write((byte_t*)l_decree->data_n_signs, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_PKEY, a_policy, dap_chain_policy_get_size(a_policy));

    dap_sign_t *l_sign = dap_cert_sign(a_cert, l_decree, sizeof(dap_chain_datum_decree_t) + l_decree->header.data_size);

    if (l_sign) {
        l_decree->header.signs_size = dap_sign_get_size(l_sign);
        l_decree = DAP_REALLOC_RET_VAL_IF_FAIL(l_decree, sizeof(dap_chain_datum_decree_t) + l_decree->header.data_size + l_decree->header.signs_size, NULL, l_decree, l_sign);
        memcpy((byte_t*)l_decree->data_n_signs + l_decree->header.data_size, l_sign, l_decree->header.signs_size);
        DAP_DELETE(l_sign);
        log_it(L_DEBUG,"<-- Signed with '%s'", a_cert->name);
    } else {
        log_it(L_ERROR, "Decree signing failed");
        DAP_DELETE(l_decree);
        return NULL;
    }
    return l_decree;
}

/**
 * @brief init policy commands
 * @return 0 if pass, other if error
 */
int dap_chain_policy_init()
{
    dap_cli_server_cmd_add ("policy", dap_chain_policy_cli, "Policy commands", "QQQ");
    return 0;
}

/**
 * @brief add new net to policies list
 * @param a_net_id
 * @return 0 if pass, other if error
 */
int dap_chain_policy_net_add(uint64_t a_net_id)
{
    dap_return_val_if_pass(!a_net_id, -1);
    if(s_net_find(a_net_id)) {
        log_it(L_ERROR, "Net with id %"DAP_UINT64_FORMAT_X" already added", a_net_id);
        return -2;
    }
    struct policy_net_list_item *l_new_item = DAP_NEW_Z_RET_VAL_IF_FAIL(struct policy_net_list_item, -3);
    l_new_item->net_id = a_net_id;
    s_net_list = dap_list_append(s_net_list, l_new_item);
    return 0;
}

/**
 * @brief remove net from policies list
 * @param a_net_id
 * @return 0 if pass, other if error
 */
int dap_chain_policy_net_remove(uint64_t a_net_id)
{
    dap_return_val_if_pass(!a_net_id, -1);
    struct policy_net_list_item *l_net_item = s_net_find(a_net_id);
    dap_list_t *l_iter = NULL;
    for (l_iter = dap_list_first(s_net_list); l_iter; l_iter = l_iter->next) {
        if ( ((struct policy_net_list_item *)(l_iter->data))->net_id == a_net_id)
            s_net_list = dap_list_remove_link(s_net_list, l_iter);
    }
    if(!l_iter) {
        log_it(L_ERROR, "Can't find net with id %"DAP_UINT64_FORMAT_X" to delete", a_net_id);
        return -2;
    }
    return 0;
}

/**
 * @brief add new policy
 * @param a_policy_num
 * @param a_net_id net id
 * @return 0 if pass, other if error
 */
int dap_chain_policy_add(dap_chain_policy_t *a_policy, uint64_t a_net_id)
{
    dap_return_val_if_pass(!a_policy, -1);
    struct policy_net_list_item *l_net_item = s_net_find(a_net_id);
    if (!l_net_item) {
        log_it(L_ERROR, "Can't find net %"DAP_UINT64_FORMAT_X" in policy list", a_net_id);
        return -2;
    }
    if (dap_list_find(l_net_item->policies, a_policy, s_policy_num_compare)) {
        log_it(L_ERROR, "CN-%u already added to net %"DAP_UINT64_FORMAT_X, a_policy->activate.num, a_net_id);
        return -3;
    }
    l_net_item->policies = dap_list_insert_sorted(l_net_item->policies, a_policy, s_policy_num_compare);
    for (size_t i = 0; i < a_policy->deactivate.count; ++i) {
        uint32_t l_policy_num = a_policy->deactivate.nums[i];
        if (dap_list_find(l_net_item->exception_list, (const void *)l_policy_num, NULL)) {
            log_it(L_ERROR, "CN-%u already added to exception list net %"DAP_UINT64_FORMAT_X, l_policy_num, a_net_id);
            continue;
        }
        l_net_item->exception_list = dap_list_insert_sorted(l_net_item->exception_list, (const void *)l_policy_num, NULL);
    }
    l_net_item->last_num_policy = dap_max(a_policy->activate.num, l_net_item->last_num_policy);
    return 0;
}

/**
 * @brief add policy num to exception list
 * @param a_policy_num
 * @param a_net_id net id
 * @return 0 if pass, other if error
 */
int dap_chain_policy_add_to_exception_list(uint32_t a_policy_num, uint64_t a_net_id)
{
    struct policy_net_list_item *l_net_item = s_net_find(a_net_id);
    if (!l_net_item) {
        log_it(L_ERROR, "Can't find net %"DAP_UINT64_FORMAT_X" in policy list", a_net_id);
        return -2;
    }
    if (dap_list_find(l_net_item->exception_list, (const void *)a_policy_num, NULL)) {
        log_it(L_ERROR, "CN-%u already added to exception list net %"DAP_UINT64_FORMAT_X, a_policy_num, a_net_id);
        return -3;
    }
    l_net_item->exception_list = dap_list_insert_sorted(l_net_item->exception_list, (const void *)a_policy_num, NULL);
    return 0;
}

/**
 * @brief check policy activation
 * @param a_policy_num
 * @param a_net_id net id
 * @return true if yes, false if no
 */
bool dap_chain_policy_activated(uint32_t a_policy_num, uint64_t a_net_id)
{
    bool l_ret = false;
    struct policy_net_list_item *l_net_item = s_net_find(a_net_id);
    dap_return_val_if_pass(!l_net_item, l_ret);
    if (l_net_item->last_num_policy < a_policy_num)
        return l_ret;
    // exception list check
    if (dap_list_find(l_net_item->exception_list, (const void *)a_policy_num, NULL))
        return l_ret;
    // seach politics to condition check
    dap_chain_policy_t l_to_search = {
        .activate.num = a_policy_num
    };
    dap_chain_policy_t *l_policy_item = (dap_chain_policy_t *)(dap_list_find(l_net_item->policies, &l_to_search, s_policy_num_compare)->data);
    
    if (!l_policy_item) {
        if (l_net_item->last_num_policy > a_policy_num)  // use cumulative principle without check conditions
            return true;
        return l_ret;
    }
    // condition check
    if (DAP_FLAG_CHECK(l_policy_item->activate.flags, DAP_CHAIN_POLICY_FLAG_ACTIVATE_BY_TS)) {
        time_t l_current_time = dap_time_now();
        if (l_current_time < l_policy_item->activate.ts_start || (l_policy_item->activate.ts_stop && l_current_time > l_policy_item->activate.ts_stop))
            return l_ret;
    }
    if (DAP_FLAG_CHECK(l_policy_item->activate.flags, DAP_CHAIN_POLICY_FLAG_ACTIVATE_BY_BLOCK_NUM)) {
        if (!l_policy_item->activate.chain_union.chain) {
            log_it(L_ERROR, "Chain is null in policy item with upped DAP_CHAIN_POLICY_FLAG_ACTIVATE_BY_BLOCK_NUM flag");
            return l_ret;
        }
        if ( l_policy_item->activate.chain_union.chain->atom_num_last < l_policy_item->activate.block_start || (l_policy_item->activate.block_stop && l_policy_item->activate.chain_union.chain->atom_num_last > l_policy_item->activate.block_stop))
            return l_ret;
    }
    return true;
}

/**
 * @brief find policy
 * @param a_policy_num
 * @param a_net_id net id
 * @return true if yes, false if no
 */
dap_chain_policy_t *dap_chain_policy_find(uint32_t a_policy_num, uint64_t a_net_id)
{
    dap_chain_policy_t *l_ret = NULL;
    struct policy_net_list_item *l_net_item = s_net_find(a_net_id);
    dap_return_val_if_pass(!l_net_item, l_ret);
    if (l_net_item->last_num_policy < a_policy_num)
        return l_ret;
    dap_chain_policy_t l_to_search = {
        .activate.num = a_policy_num
    };
    l_ret = (dap_chain_policy_t *)(dap_list_find(l_net_item->policies, &l_to_search, s_policy_num_compare)->data);
    if (!l_ret) {
        log_it(L_ERROR, "Can't find CN-%u in net %"DAP_UINT64_FORMAT_X, a_policy_num, a_net_id);
    }
    return l_ret;
}

/**
 * @brief return last policy num in enet
 * @param a_net_id net id to search
 * @return last num
 */
DAP_INLINE uint32_t dap_chain_policy_get_last_num(uint64_t a_net_id)
{
    struct policy_net_list_item *l_net_item = s_net_find(a_net_id);
    dap_return_val_if_pass(!l_net_item, 0);
    return l_net_item->last_num_policy;
}


static json_object *s_json_collect_policy(dap_chain_policy_t *a_policy)
{
    dap_return_val_if_pass(!a_policy, NULL);
    json_object *l_ret = json_object_new_object();

    json_object_object_add(l_ret, "version", json_object_new_uint64(a_policy->version));
    json_object_object_add(l_ret, "num", json_object_new_uint64(a_policy->activate.num));
    if (a_policy->activate.ts_start) {
        char l_time[DAP_TIME_STR_SIZE] = {};
        dap_time_to_str_rfc822(l_time, DAP_TIME_STR_SIZE - 1, a_policy->activate.ts_start);
        json_object_object_add(l_ret, "ts_start", json_object_new_string(l_time));
    } else {
        json_object_object_add(l_ret, "ts_start", json_object_new_int(0));
    }
    if (a_policy->activate.ts_stop) {
        char l_time[DAP_TIME_STR_SIZE] = {};
        dap_time_to_str_rfc822(l_time, DAP_TIME_STR_SIZE - 1, a_policy->activate.ts_stop);
        json_object_object_add(l_ret, "ts_stop", json_object_new_string(l_time));
    } else {
        json_object_object_add(l_ret, "ts_stop", json_object_new_int(0));
    }
    json_object_object_add(l_ret, "block_start", json_object_new_uint64(a_policy->activate.block_start));
    json_object_object_add(l_ret, "block_stop", json_object_new_uint64(a_policy->activate.block_stop));
    if (a_policy->activate.block_start || a_policy->activate.block_stop) {
        char l_chain_id[32] = { };
        snprintf(l_chain_id, sizeof(l_chain_id) - 1, "0x%016"DAP_UINT64_FORMAT_x, a_policy->activate.chain_union.chain_id.uint64);
        json_object_object_add(l_ret, "chain", json_object_new_string(l_chain_id));
    } else {
        json_object_object_add(l_ret, "chain", json_object_new_string(""));
    }
    if (a_policy->deactivate.count) {
        dap_string_t *l_nums_list = dap_string_sized_new(a_policy->deactivate.count * (sizeof(uint32_t) + 1));
        for (size_t i = 0; i < a_policy->deactivate.count; ++i) {
            dap_string_append_printf(l_nums_list, "%u ", a_policy->deactivate.nums[i]);
        }
        json_object_object_add(l_ret, "deactivate", json_object_new_string(l_nums_list->str));
        dap_string_free(l_nums_list, true);
    } else {
        json_object_object_add(l_ret, "deactivate", json_object_new_string(""));
    }
    json_object_object_add(l_ret, "description", json_object_new_string("WIKI"));
    return l_ret;
}

int dap_chain_policy_cli(int argc, char **argv, void **reply) {
    json_object ** a_json_arr_reply = (json_object **) reply;
    char **l_deactivate_array = NULL;
    const char
        *l_execute_str = NULL,
        *l_num_str = NULL,
        *l_show_str = NULL,
        *l_net_str = NULL,
        *l_deactivate_str = NULL,
        *l_chain_str = NULL,
        *l_ts_start_str = NULL,
        *l_ts_stop_str = NULL,
        *l_block_start_str = NULL,
        *l_block_stop_str = NULL,
        *l_cert_str = NULL;
    size_t l_deactivate_count = 0;

    int l_arg_index = 1;
    dap_cli_server_cmd_find_option_val(argv, l_arg_index, argc, "execute", &l_execute_str);
    dap_cli_server_cmd_find_option_val(argv, l_arg_index, argc, "show", &l_show_str);
    dap_cli_server_cmd_find_option_val(argv, l_arg_index, argc, "-num", &l_num_str);
    dap_cli_server_cmd_find_option_val(argv, l_arg_index, argc, "-net", &l_net_str);
    dap_cli_server_cmd_find_option_val(argv, l_arg_index, argc, "-chain", &l_chain_str);
    dap_cli_server_cmd_find_option_val(argv, l_arg_index, argc, "-ts_start", &l_ts_start_str);
    dap_cli_server_cmd_find_option_val(argv, l_arg_index, argc, "-ts_stop", &l_ts_stop_str);
    dap_cli_server_cmd_find_option_val(argv, l_arg_index, argc, "-block_start", &l_block_start_str);
    dap_cli_server_cmd_find_option_val(argv, l_arg_index, argc, "-block_stop", &l_block_stop_str);
    dap_cli_server_cmd_find_option_val(argv, l_arg_index, argc, "-deactivate", &l_deactivate_str);
    dap_cli_server_cmd_find_option_val(argv, l_arg_index, argc, "-poa_cert", &l_cert_str);

    if ((!l_execute_str && !l_show_str) || (l_execute_str && l_show_str)) {
        dap_json_rpc_error_add(*a_json_arr_reply, -2, "Command policy require subcommand execute or show");
        return -2;
    }

    if (!l_net_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, -3, "Command policy require args -net");
        return -4;
    }
    dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
    if (!l_net){
        dap_json_rpc_error_add(*a_json_arr_reply, -3, "Can't find net %s", l_net_str);
        return -4;
    }

    if (l_execute_str && !l_cert_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, -4, "Command 'execute' requires parameter -poa_cert");
        return -4;
    }
    dap_cert_t *l_cert = dap_cert_find_by_name(l_cert_str);
    if (!l_cert) {
        dap_json_rpc_error_add(*a_json_arr_reply, -5, "Specified certificate not found");
        return -5;
    }
    if (!s_srv_stake_is_poa_cert(l_net, l_cert->enc_key)) {
        dap_json_rpc_error_add(*a_json_arr_reply, -6, "Specified certificate is not PoA root one");
        return -6;
    }

    if (!l_num_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, -7, "Command policy require args -num");
        return -7;
    }

    if (l_deactivate_str) {
        l_deactivate_count = dap_str_symbol_count(l_deactivate_str, ',') + 1;
        l_deactivate_array = dap_strsplit(l_deactivate_str, ",", l_deactivate_count);
    }
    dap_chain_policy_t *l_policy = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_policy_t, sizeof(dap_chain_policy_t) + l_deactivate_count * sizeof(uint32_t), -5);
    
    l_policy->version = DAP_CHAIN_POLICY_VERSION;
    l_policy->activate.num = strtoull(l_num_str, NULL, 10);

    l_policy->deactivate.count = l_deactivate_count;
    for (size_t i = 0; i < l_deactivate_count; ++i) {
        l_policy->deactivate.nums[i] = strtoul(l_deactivate_array[i], NULL, 10);
    }
    dap_strfreev(l_deactivate_array);


    if (l_ts_start_str) {
        struct tm l_tm = { };
        strptime(l_ts_start_str, "%d/%m/%Y-%H:%M:%S", &l_tm);
        l_tm.tm_year += 2000;
        l_policy->activate.ts_start = mktime(&l_tm);
    }

    if (l_ts_stop_str) {
        struct tm l_tm = { };
        strptime(l_ts_stop_str, "%d/%m/%Y-%H:%M:%S", &l_tm);
        l_tm.tm_year += 2000;
        l_policy->activate.ts_stop = mktime(&l_tm);
    }

    if (l_policy->activate.ts_start || l_policy->activate.ts_stop) {
        l_policy->activate.flags = DAP_FLAG_ADD(l_policy->activate.flags, DAP_CHAIN_POLICY_FLAG_ACTIVATE_BY_TS);
    }

    if (l_block_start_str)
        l_policy->activate.block_start = strtoull(l_block_start_str, NULL, 10);
    if (l_block_stop_str)
        l_policy->activate.block_stop = strtoull(l_block_stop_str, NULL, 10);
    
    if (l_policy->activate.block_start || l_policy->activate.block_stop) {
        if (!l_chain_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, -5, "Command policy create with -block_start or -block_stop require args -chain");
            DAP_DELETE(l_policy);
            return -8;
        }
        dap_chain_t *l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_str);
        if (!l_chain) {
            dap_json_rpc_error_add(*a_json_arr_reply, -6, "%s Chain not found", l_chain_str);
            DAP_DELETE(l_policy);
            return -9;
        }
        l_policy->activate.chain_union.chain_id = l_chain->id;
        l_policy->activate.flags = DAP_FLAG_ADD(l_policy->activate.flags, DAP_CHAIN_POLICY_FLAG_ACTIVATE_BY_BLOCK_NUM);
    }
    // if cmd show - only print preaparing result
    if (l_show_str) {
        json_object *l_answer = s_json_collect_policy(l_policy);
        if (l_answer) {
            json_object_array_add(*a_json_arr_reply, l_answer);
        } else {
            json_object_array_add(*a_json_arr_reply, json_object_new_string("Empty reply"));
        }
        DAP_DELETE(l_policy);
        return 0;
    }

    dap_chain_datum_decree_t *l_decree = s_decree_policy_execute(l_net, l_cert, l_policy);
    DAP_DELETE(l_policy);
    char *l_decree_hash_str = NULL;
    if (!l_decree || !(l_decree_hash_str = s_stake_decree_put(l_decree, l_net))) {
        dap_json_rpc_error_add(*a_json_arr_reply, -10, "policy execute decree error");
        return -10;
    }
    DAP_DELETE(l_decree);
    char *l_approve_str = dap_strdup_printf("policy execute decree %s successfully created", l_decree_hash_str);
    json_object_array_add(*a_json_arr_reply, json_object_new_string(l_approve_str));
    DAP_DEL_MULTY(l_decree_hash_str, l_approve_str);

    return 0;
}