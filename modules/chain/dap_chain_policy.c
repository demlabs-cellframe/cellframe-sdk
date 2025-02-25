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
#include "dap_chain_datum_decree.h"
#include "dap_list.h"

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

/**
 * @brief init policy commands
 * @return 0 if pass, other if error
 */
int dap_chain_policy_init()
{
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
    dap_list_t *l_net_item = dap_list_first(s_net_list);
    for ( ; l_net_item && ((struct policy_net_list_item *)(l_net_item->data))->net_id != a_net_id; l_net_item = l_net_item->next) {};

    if (!l_net_item) {
        log_it(L_ERROR, "Can't find net %"DAP_UINT64_FORMAT_X" in policy list", a_net_id);
        return -2;
    }
    s_net_list = dap_list_remove_link(s_net_list, l_net_item);
    dap_list_free_full(((struct policy_net_list_item *)(l_net_item->data))->policies, NULL);
    dap_list_free(((struct policy_net_list_item *)(l_net_item->data))->exception_list);
    DAP_DEL_MULTY(l_net_item->data, l_net_item);
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
        if (dap_list_find(l_net_item->exception_list, (const void *)(uintptr_t)l_policy_num, NULL)) {
            log_it(L_ERROR, "CN-%u already added to exception list net %"DAP_UINT64_FORMAT_X, l_policy_num, a_net_id);
            continue;
        }
        l_net_item->exception_list = dap_list_append(l_net_item->exception_list, (void *)(uintptr_t)l_policy_num);
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
    if (dap_list_find(l_net_item->exception_list, (const void *)(uintptr_t)a_policy_num, NULL)) {
        log_it(L_ERROR, "CN-%u already added to exception list net %"DAP_UINT64_FORMAT_X, a_policy_num, a_net_id);
        return -3;
    }
    l_net_item->exception_list = dap_list_append(l_net_item->exception_list, (void *)(uintptr_t)a_policy_num);
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
    if (dap_list_find(l_net_item->exception_list, (const void *)(uintptr_t)a_policy_num, NULL))
        return l_ret;
    // seach politics to condition check
    dap_chain_policy_t l_to_search = {
        .activate.num = a_policy_num
    };
    dap_list_t *l_list_item = dap_list_find(l_net_item->policies, &l_to_search, s_policy_num_compare);
    if (!l_list_item) {
        if (l_net_item->last_num_policy > a_policy_num)  // use cumulative principle without check conditions
            return true;
        return l_ret;
    }
    dap_chain_policy_t *l_policy_item = (dap_chain_policy_t *)l_list_item->data;
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
    struct policy_net_list_item *l_net_item = s_net_find(a_net_id);
    dap_return_val_if_pass(!l_net_item, NULL);
    if (l_net_item->last_num_policy < a_policy_num)
        return NULL;
    dap_chain_policy_t l_to_search = {
        .activate.num = a_policy_num
    };
    dap_list_t *l_find = dap_list_find(l_net_item->policies, &l_to_search, s_policy_num_compare);
    if (!l_find) {
        log_it(L_DEBUG, "Can't find CN-%u in net %"DAP_UINT64_FORMAT_X, a_policy_num, a_net_id);
        return NULL;
    }
    return (dap_chain_policy_t *)l_find->data;
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


json_object *dap_chain_policy_list(uint64_t a_net_id)
{
    struct policy_net_list_item *l_net_item = s_net_find(a_net_id);
    dap_return_val_if_pass(!l_net_item, NULL);
    json_object *l_ret = json_object_new_object();

    dap_string_t *l_add_str = dap_string_new("");
    for (dap_list_t *l_iter = dap_list_first(l_net_item->policies); l_iter; l_iter = l_iter->next) {
        dap_string_append_printf(l_add_str, "CN-%u ", ((dap_chain_policy_t *)l_iter->data)->activate.num);
    }
    json_object_object_add(l_ret, "active", json_object_new_string(l_add_str->str));
    
    dap_string_erase(l_add_str, 0, -1);
    for (dap_list_t *l_iter = dap_list_first(l_net_item->exception_list); l_iter; l_iter = l_iter->next) {
        dap_string_append_printf(l_add_str, "CN-%u ", (uint32_t)(uintptr_t)l_iter->data);
    }
    json_object_object_add(l_ret, "inactive", json_object_new_string(l_add_str->str));
    dap_string_free(l_add_str, true);
    return l_ret;
}

json_object *dap_chain_policy_json_collect(dap_chain_policy_t *a_policy)
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
        if (!a_policy->activate.chain_union.chain) {
            json_object_object_add(l_ret, "chain", json_object_new_string("ERROR pointer chain is NULL"));
        } else {
            char l_chain_id[32] = { };
            snprintf(l_chain_id, sizeof(l_chain_id) - 1, "0x%016"DAP_UINT64_FORMAT_x, a_policy->activate.chain_union.chain->id.uint64);
            json_object_object_add(l_ret, "chain", json_object_new_string(l_chain_id));
        }
    } else {
        json_object_object_add(l_ret, "chain", json_object_new_string(""));
    }
    if (a_policy->deactivate.count) {
        dap_string_t *l_nums_list = dap_string_sized_new(a_policy->deactivate.count * (sizeof(uint32_t) + 4));
        for (size_t i = 0; i < a_policy->deactivate.count; ++i) {
            dap_string_append_printf(l_nums_list, "CN-%u ", a_policy->deactivate.nums[i]);
        }
        json_object_object_add(l_ret, "deactivate", json_object_new_string(l_nums_list->str));
        dap_string_free(l_nums_list, true);
    } else {
        json_object_object_add(l_ret, "deactivate", json_object_new_string(""));
    }
    json_object_object_add(l_ret, "description", json_object_new_string("WIKI"));
    return l_ret;
}