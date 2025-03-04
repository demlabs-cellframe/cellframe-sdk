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
    dap_chain_policy_t
        *l_policy1 = a_list1->data,
        *l_policy2 = a_list2->data;
    if (l_policy1->type != DAP_CHAIN_POLICY_ACTIVATE || l_policy2->type != DAP_CHAIN_POLICY_ACTIVATE) {
        log_it(L_WARNING, "Compare wrong policy type");
        return 0;
    }
    return ((dap_chain_policy_activate_t *)(l_policy1->data))->num == ((dap_chain_policy_activate_t *)(l_policy2->data))->num ? 0 :
        ((dap_chain_policy_activate_t *)(l_policy1->data))->num > ((dap_chain_policy_activate_t *)(l_policy2->data))->num ? 1 : -1;
}

DAP_STATIC_INLINE bool s_policy_is_cond(dap_chain_policy_t *a_policy)
{
    return a_policy->type == DAP_CHAIN_POLICY_ACTIVATE &&
        (DAP_FLAG_CHECK(((dap_chain_policy_activate_t *)(a_policy->data))->flags, DAP_CHAIN_POLICY_FLAG_ACTIVATE_BY_TS) ||
        DAP_FLAG_CHECK(((dap_chain_policy_activate_t *)(a_policy->data))->flags, DAP_CHAIN_POLICY_FLAG_ACTIVATE_BY_BLOCK_NUM));
}

static bool s_policy_cond_activated(dap_chain_policy_activate_t *a_policy_activate)
{
    bool l_ret = false;
    if (DAP_FLAG_CHECK(a_policy_activate->flags, DAP_CHAIN_POLICY_FLAG_ACTIVATE_BY_TS)) {
        time_t l_current_time = dap_time_now();
        if (l_current_time >= a_policy_activate->ts_start && (!a_policy_activate->ts_stop || l_current_time <= a_policy_activate->ts_stop))
        l_ret |= true;
    }
    if (DAP_FLAG_CHECK(a_policy_activate->flags, DAP_CHAIN_POLICY_FLAG_ACTIVATE_BY_BLOCK_NUM)) {
        if (!a_policy_activate->chain_union.chain) {
            log_it(L_ERROR, "Chain is null in policy item with upped DAP_CHAIN_POLICY_FLAG_ACTIVATE_BY_BLOCK_NUM flag");
            return l_ret;
        }
        if ( a_policy_activate->chain_union.chain->atom_num_last >= a_policy_activate->block_start && (!a_policy_activate->block_stop || a_policy_activate->chain_union.chain->atom_num_last <= a_policy_activate->block_stop))
            l_ret |= true;
    }
    return l_ret;
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
    switch (a_policy->type) {
        case DAP_CHAIN_POLICY_ACTIVATE:
            if (dap_list_find(l_net_item->policies, a_policy, s_policy_num_compare)) {
                log_it(L_ERROR, "CN-%u already added to net %"DAP_UINT64_FORMAT_X, ((dap_chain_policy_activate_t *)(a_policy->data))->num, a_net_id);
                return -3;
            }
            l_net_item->policies = dap_list_insert_sorted(l_net_item->policies, a_policy, s_policy_num_compare);
            l_net_item->last_num_policy = dap_max(((dap_chain_policy_activate_t *)(a_policy->data))->num, l_net_item->last_num_policy);
            break;
        case DAP_CHAIN_POLICY_DEACTIVATE:
            for (size_t i = 0; i < ((dap_chain_policy_deactivate_t *)(a_policy->data))->count; ++i) {
                uint32_t l_policy_num = ((dap_chain_policy_deactivate_t *)(a_policy->data))->nums[i];
                if (dap_list_find(l_net_item->exception_list, (const void *)(uintptr_t)l_policy_num, NULL)) {
                    log_it(L_ERROR, "CN-%u already added to exception list net %"DAP_UINT64_FORMAT_X, l_policy_num, a_net_id);
                    continue;
                }
                l_net_item->exception_list = dap_list_append(l_net_item->exception_list, (void *)(uintptr_t)l_policy_num);
            }
            break;
        default:
            log_it(L_ERROR, "Unknow policy type %u", a_policy->type);
            break;
    }
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
    dap_return_val_if_pass(!a_policy_num, -1);
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
    const bool l_ret_false = false;
    struct policy_net_list_item *l_net_item = s_net_find(a_net_id);
    dap_return_val_if_pass(!l_net_item, l_ret_false);
    // exception list check
    if (dap_list_find(l_net_item->exception_list, (const void *)(uintptr_t)a_policy_num, NULL))
        return l_ret_false;
    // seach politics to condition check
    dap_chain_policy_t *l_to_search = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_policy_t, sizeof(dap_chain_policy_t) + sizeof(dap_chain_policy_activate_t), false);
    l_to_search->type = DAP_CHAIN_POLICY_ACTIVATE;
    ((dap_chain_policy_activate_t *)(l_to_search->data))->num = a_policy_num;
    dap_list_t *l_list_item = dap_list_find(l_net_item->policies, l_to_search, s_policy_num_compare);
    DAP_DELETE(l_to_search);
    if (l_list_item && s_policy_is_cond((dap_chain_policy_t *)l_list_item->data)) {
        return s_policy_cond_activated((dap_chain_policy_activate_t *)((dap_chain_policy_t *)(l_list_item->data))->data);
    }
    // cumulative return
    return a_policy_num <= l_net_item->last_num_policy;
}

/**
 * @brief find policy
 * @param a_policy_num
 * @param a_net_id net id
 * @return true if yes, false if no
 */
dap_chain_policy_t *dap_chain_policy_find(uint32_t a_policy_num, uint64_t a_net_id)
{
    dap_return_val_if_pass(!a_policy_num, NULL);
    struct policy_net_list_item *l_net_item = s_net_find(a_net_id);
    dap_return_val_if_pass(!l_net_item, NULL);
    if (l_net_item->last_num_policy < a_policy_num)
        return NULL;

    dap_chain_policy_t *l_to_search = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_policy_t, sizeof(dap_chain_policy_t) + sizeof(dap_chain_policy_activate_t), false);
    l_to_search->type = DAP_CHAIN_POLICY_ACTIVATE;
    ((dap_chain_policy_activate_t *)(l_to_search->data))->num = a_policy_num;
    dap_list_t *l_find = dap_list_find(l_net_item->policies, l_to_search, s_policy_num_compare);
    DAP_DELETE(l_to_search);
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

    dap_string_t *l_active_str = dap_string_new("");
    dap_string_t *l_inactive_str = dap_string_new("");
    if (l_net_item->last_num_policy)
        dap_string_append_printf(l_active_str, "%s CN-%u ", dap_list_find(l_net_item->exception_list, (const void *)(uintptr_t)l_net_item->last_num_policy, NULL) ? "<" : "<=", l_net_item->last_num_policy);
    json_object_object_add(l_ret, "cumulative active", json_object_new_string(l_active_str->str));
    dap_string_erase(l_active_str, 0, -1);
    for (dap_list_t *l_iter = dap_list_first(l_net_item->policies); l_iter; l_iter = l_iter->next) {
        dap_chain_policy_activate_t *l_policy_activate =  (dap_chain_policy_activate_t *)((dap_chain_policy_t *)(l_iter->data))->data;
        if (dap_list_find(l_net_item->exception_list, (const void *)(uintptr_t)l_policy_activate->num, NULL))
            continue;
        if (s_policy_is_cond((dap_chain_policy_t *)(l_iter->data))) {
            if (s_policy_cond_activated(l_policy_activate))
                dap_string_append_printf(l_active_str, "CN-%u ", l_policy_activate->num);
            else
                dap_string_append_printf(l_inactive_str, "CN-%u ", l_policy_activate->num);
        }
    }
    json_object_object_add(l_ret, "conditional active", json_object_new_string(l_active_str->str));
    json_object_object_add(l_ret, "conditional inactive", json_object_new_string(l_inactive_str->str));
    
    dap_string_free(l_active_str, true);
    dap_string_erase(l_inactive_str, 0, -1);
    for (dap_list_t *l_iter = dap_list_first(l_net_item->exception_list); l_iter; l_iter = l_iter->next) {
        dap_string_append_printf(l_inactive_str, "CN-%u ", (uint32_t)(uintptr_t)l_iter->data);
    }
    json_object_object_add(l_ret, "exception list", json_object_new_string(l_inactive_str->str));
    dap_string_free(l_inactive_str, true);
    return l_ret;
}

json_object *dap_chain_policy_json_collect(dap_chain_policy_t *a_policy)
{
    dap_return_val_if_pass(!a_policy, NULL);
    json_object *l_ret = json_object_new_object();

    json_object_object_add(l_ret, "version", json_object_new_uint64(a_policy->version));
    json_object_object_add(l_ret, "type", json_object_new_string(dap_chain_policy_to_str(a_policy)));
    switch (a_policy->type) {
        case DAP_CHAIN_POLICY_ACTIVATE: {
            dap_chain_policy_activate_t *l_policy_activate = (dap_chain_policy_activate_t *)a_policy->data;
            json_object_object_add(l_ret, "num", json_object_new_uint64(l_policy_activate->num));
            if (l_policy_activate->ts_start) {
                char l_time[DAP_TIME_STR_SIZE] = {};
                dap_time_to_str_rfc822(l_time, DAP_TIME_STR_SIZE - 1, l_policy_activate->ts_start);
                json_object_object_add(l_ret, "ts_start", json_object_new_string(l_time));
            } else {
                json_object_object_add(l_ret, "ts_start", json_object_new_int(0));
            }
            if (l_policy_activate->ts_stop) {
                char l_time[DAP_TIME_STR_SIZE] = {};
                dap_time_to_str_rfc822(l_time, DAP_TIME_STR_SIZE - 1, l_policy_activate->ts_stop);
                json_object_object_add(l_ret, "ts_stop", json_object_new_string(l_time));
            } else {
                json_object_object_add(l_ret, "ts_stop", json_object_new_int(0));
            }
            json_object_object_add(l_ret, "block_start", json_object_new_uint64(l_policy_activate->block_start));
            json_object_object_add(l_ret, "block_stop", json_object_new_uint64(l_policy_activate->block_stop));
            if (l_policy_activate->block_start || l_policy_activate->block_stop) {
                if (!l_policy_activate->chain_union.chain) {
                    json_object_object_add(l_ret, "chain", json_object_new_string("ERROR pointer chain is NULL"));
                } else {
                    char l_chain_id[32] = { };
                    snprintf(l_chain_id, sizeof(l_chain_id) - 1, "0x%016"DAP_UINT64_FORMAT_x, l_policy_activate->chain_union.chain->id.uint64);
                    json_object_object_add(l_ret, "chain", json_object_new_string(l_chain_id));
                }
            } else {
                json_object_object_add(l_ret, "chain", json_object_new_string(""));
            }
            json_object_object_add(l_ret, "description", json_object_new_string("WIKI"));
        }
            break;
        
        case DAP_CHAIN_POLICY_DEACTIVATE: {
            dap_chain_policy_deactivate_t *l_policy_deactivate = (dap_chain_policy_deactivate_t *)a_policy->data;
            if (l_policy_deactivate->count) {
                dap_string_t *l_nums_list = dap_string_sized_new(l_policy_deactivate->count * (sizeof(uint32_t) + 4));
                for (size_t i = 0; i < l_policy_deactivate->count; ++i) {
                    dap_string_append_printf(l_nums_list, "CN-%u ", l_policy_deactivate->nums[i]);
                }
                json_object_object_add(l_ret, "deactivate", json_object_new_string(l_nums_list->str));
                dap_string_free(l_nums_list, true);
            } else {
                json_object_object_add(l_ret, "deactivate", json_object_new_string(""));
            }
        }
            break;
        default:
            break;
    }
    return l_ret;
}