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
#include "dap_chain.h"
#include "dap_chain_datum_decree.h"
#include "dap_list.h"
#include "uthash.h"

#define LOG_TAG "dap_chain_policy"

typedef struct dap_chain_policy_deactivate {
    uint32_t count;
    uint32_t nums[];
} DAP_ALIGN_PACKED dap_chain_policy_deactivate_t;

typedef struct dap_chain_policy_activate {
    uint32_t num;
    int64_t ts_start;
    uint64_t block_start;
    dap_chain_id_t chain_id;
    uint16_t generation;
} DAP_ALIGN_PACKED dap_chain_policy_activate_t;

struct policy_activate_table {
    dap_chain_policy_activate_t *policy;
    UT_hash_handle hh;
};

struct net_policy_item {
    dap_chain_net_id_t net_id;
    atomic_uint_fast32_t last_num_policy;
    uint32_t *exceptions;  // [0] - exceptions count
    struct policy_activate_table *policies;
    UT_hash_handle hh;
};

static struct net_policy_item *s_net_policy_items = NULL;

/**
 * @brief search net element in list by id
 * @param a_net_id
 * @return pointer if find, NULL if not
 */
DAP_STATIC_INLINE struct net_policy_item *s_net_item_find(dap_chain_net_id_t a_net_id)
{
    struct net_policy_item *l_net_item = NULL;
    HASH_FIND_BYHASHVALUE(hh, s_net_policy_items, &a_net_id, sizeof(a_net_id), a_net_id.uint64, l_net_item);
    return l_net_item;
}


DAP_STATIC_INLINE dap_chain_policy_activate_t *s_policy_activate_find(dap_chain_net_id_t a_net_id, uint32_t a_num)
{
    struct net_policy_item *l_net_item = s_net_item_find(a_net_id);
    if (!l_net_item) {
        return NULL;
    }
    struct policy_activate_table *l_ret = NULL;
    HASH_FIND_BYHASHVALUE(hh, l_net_item->policies, &a_num, sizeof(a_num), a_num, l_ret);
    return l_ret ? l_ret->policy : NULL;
}

DAP_STATIC_INLINE void s_net_item_free(struct net_policy_item *a_item)
{
    dap_return_if_pass(!a_item);
    struct policy_activate_table
        *l_temp = NULL,
        *l_current = NULL;
    HASH_ITER(hh, a_item->policies, l_current, l_temp) {
        HASH_DEL(s_net_policy_items, l_current);
        DAP_DELETE(l_current);
    }
}

DAP_STATIC_INLINE bool s_policy_is_cond(dap_chain_policy_activate_t *a_policy)
{
    return a_policy->block_start || a_policy->ts_start;
}

DAP_STATIC_INLINE bool s_policy_in_exceptions(struct net_policy_item *l_net_item, uint32_t a_num)
{
    if (l_net_item && l_net_item->exceptions)
        for (uint32_t i = 1; i < l_net_item->exceptions[0]; ++i) {
            if (l_net_item->exceptions[i] == a_num)
                return true;
        }
    return false;
}

static bool s_policy_cond_activated(dap_chain_net_id_t a_net_id, dap_chain_policy_activate_t *a_policy_activate)
{
    bool l_ret = a_policy_activate->ts_start && dap_time_now() > a_policy_activate->ts_start;

    if (!l_ret && a_policy_activate->block_start) {
        dap_chain_t *l_chain = dap_chain_find_by_id(a_net_id, a_policy_activate->chain_id);
        if (!l_chain) {
            log_it(L_ERROR, "Chain is null in policy item with upped DAP_CHAIN_POLICY_FLAG_ACTIVATE_BY_BLOCK_NUM flag");
            return l_ret;
        }
        l_ret |= l_chain->atom_num_last >= a_policy_activate->block_start;
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

void dap_chain_policy_deinit_by_net(dap_chain_net_id_t a_net_id)
{
    dap_return_if_pass(!a_net_id.uint64);
    struct net_policy_item *l_net_item = s_net_item_find(a_net_id);
    if (!l_net_item) {
        log_it(L_ERROR, "Can't find net %"DAP_UINT64_FORMAT_X" in policy list", a_net_id);
        return -2;
    }
    s_net_item_free(l_net_item);
}

/**
 * @brief deinit policy commands
 */
void dap_chain_policy_deinit()
{
    struct net_policy_item
        *l_temp = NULL,
        *l_current = NULL;
    HASH_ITER(hh, s_net_policy_items, l_current, l_temp) {
        HASH_DEL(s_net_policy_items, l_current);
        s_net_item_free(l_current);
    }
}

/**
 * @brief add new net to policies list
 * @param a_net_id
 * @return 0 if pass, other if error
 */
int dap_chain_policy_net_add(dap_chain_net_id_t a_net_id)
{
    dap_return_val_if_pass(!a_net_id.uint64, -1);
    if(s_net_item_find(a_net_id)) {
        log_it(L_ERROR, "Net with id %"DAP_UINT64_FORMAT_X" already added", a_net_id);
        return -2;
    }
    struct net_policy_item *l_new_item = DAP_NEW_Z_RET_VAL_IF_FAIL(struct net_policy_item, -3);
    l_new_item->net_id = a_net_id;
    HASH_ADD_BYHASHVALUE(hh, s_net_policy_items, net_id, sizeof(l_new_item->net_id), l_new_item->net_id.uint64, l_new_item);
    return 0;
}

/**
 * @brief add new policy
 * @param a_policy_num
 * @param a_net_id net id
 * @return 0 if pass, other if error
 */
int dap_chain_policy_add(dap_chain_policy_t *a_policy, dap_chain_net_id_t a_net_id)
{
    dap_return_val_if_pass(!a_policy || !a_policy->data_size || !a_policy->data, -1);
    if (!DAP_FLAG_CHECK(a_policy->flags, DAP_CHAIN_POLICY_FLAG_ACTIVATE)) {
        log_it(L_ERROR, "Can't add deactivation to policy activate list in net %"DAP_UINT64_FORMAT_X, a_net_id);
        return -2;
    }
    struct net_policy_item *l_net_item = s_net_item_find(a_net_id);
    if (!l_net_item) {
        log_it(L_ERROR, "Can't find net %"DAP_UINT64_FORMAT_X" in policy list", a_net_id);
        return -3;
    }
    dap_chain_policy_activate_t *l_to_add = (dap_chain_policy_activate_t *)a_policy->data;
    struct policy_activate_table *l_item = NULL;
    HASH_FIND_BYHASHVALUE(hh, l_net_item->policies, &l_to_add->num, sizeof(l_to_add->num), l_to_add->num, l_item);
    if (l_item) {
        log_it(L_ERROR, "CN-%u already added to net %"DAP_UINT64_FORMAT_X, ((dap_chain_policy_activate_t *)(a_policy->data))->num, a_net_id);
        return -4;
    }
    l_item = DAP_NEW_Z_RET_VAL_IF_FAIL(struct policy_activate_table, -5);
    l_item->policy = l_to_add;
    HASH_ADD_BYHASHVALUE(hh, l_net_item->policies, policy->num, sizeof(l_item->policy->num), l_item->policy->num, l_item);
    if (!s_policy_is_cond(l_item->policy))
        l_net_item->last_num_policy = dap_max(l_item->policy->num, l_net_item->last_num_policy);
}

/**
 * @brief add new policy
 * @param a_policy_num
 * @param a_net_id net id
 * @return 0 if pass, other if error
 */
int dap_chain_policy_exceptions_add(dap_chain_net_id_t a_net_id, char **a_nums)
{
    dap_return_val_if_pass(!a_nums, -1);
    struct net_policy_item *l_net_item = s_net_item_find(a_net_id);
    if (!l_net_item) {
        log_it(L_ERROR, "Can't find net %"DAP_UINT64_FORMAT_X" in policy list", a_net_id);
        return -2;
    }
    if (l_net_item->exceptions) {
        log_it(L_ERROR, "Exception list already exist in net %"DAP_UINT64_FORMAT_X"", a_net_id);
        return -3;
    }

    return 0;
}

/**
 * @brief add new policy
 * @param a_policy_num
 * @param a_net_id net id
 * @return 0 if pass, other if error
 */
int dap_chain_policy_last_num_update(dap_chain_net_id_t a_net_id, uint32_t a_num)
{
    struct net_policy_item *l_net_item = s_net_item_find(a_net_id);
    if (!l_net_item) {
        log_it(L_ERROR, "Can't find net %"DAP_UINT64_FORMAT_X" in policy list", a_net_id);
        return -2;
    }
    l_net_item->last_num_policy = dap_max(a_num, l_net_item->last_num_policy);
    return 0;
}

/**
 * @brief check policy activation
 * @param a_policy_num
 * @param a_net_id net id
 * @return true if yes, false if no
 */
bool dap_chain_policy_activated(uint32_t a_policy_num, dap_chain_net_id_t a_net_id)
{
    const bool l_ret_false = false;
    struct net_policy_item *l_net_item = s_net_item_find(a_net_id);
    dap_return_val_if_pass(!l_net_item, l_ret_false);
    // exception list check
    if (s_policy_in_exceptions(l_net_item, a_policy_num))
        return l_ret_false;
    // seach politics to condition check
    struct policy_activate_table *l_policy_activate = NULL;
    HASH_FIND_BYHASHVALUE(hh, l_net_item->policies, &a_policy_num, sizeof(a_policy_num), a_policy_num, l_policy_activate);
    if (l_policy_activate && s_policy_is_cond(l_policy_activate->policy)) {
        bool l_ret = s_policy_cond_activated(a_net_id, l_policy_activate->policy);
        if (l_ret)
            l_net_item->last_num_policy = dap_max(a_policy_num, l_net_item->last_num_policy);
        return l_ret;
    }
    // cumulative return
    return a_policy_num <= l_net_item->last_num_policy;
}

/**
 * @brief return last policy num in enet
 * @param a_net_id net id to search
 * @return last num
 */
DAP_INLINE uint32_t dap_chain_policy_get_last_num(dap_chain_net_id_t a_net_id)
{
    struct net_policy_item *l_net_item = s_net_item_find(a_net_id);
    dap_return_val_if_pass(!l_net_item, 0);
    return l_net_item->last_num_policy;
}


json_object *dap_chain_policy_list(dap_chain_net_id_t a_net_id)
{
    struct net_policy_item *l_net_item = s_net_item_find(a_net_id);
    dap_return_val_if_pass(!l_net_item, NULL);
    json_object *l_ret = json_object_new_object();

    dap_string_t *l_active_str = dap_string_new("");
    dap_string_t *l_inactive_str = dap_string_new("");
    if (l_net_item->last_num_policy)
        dap_string_append_printf(l_active_str, "%s CN-%u ", s_policy_in_exceptions(l_net_item, l_net_item->last_num_policy) ? "<" : "<=", l_net_item->last_num_policy);
    json_object_object_add(l_ret, "cumulative active", json_object_new_string(l_active_str->str));
    dap_string_erase(l_active_str, 0, -1);
    struct policy_activate_table
        *l_temp = NULL,
        *l_current = NULL;
    HASH_ITER(hh, l_net_item->policies, l_current, l_temp) {
        if (s_policy_is_cond(l_current->policy)) {
            if (s_policy_cond_activated(l_net_item->net_id, l_current->policy))
                dap_string_append_printf(l_active_str, "CN-%u ", l_current->policy->num);
            else
                dap_string_append_printf(l_inactive_str, "CN-%u ", l_current->policy->num);
        }
    }
    json_object_object_add(l_ret, "conditional active", json_object_new_string(l_active_str->str));
    json_object_object_add(l_ret, "conditional inactive", json_object_new_string(l_inactive_str->str));
    
    dap_string_free(l_active_str, true);
    dap_string_erase(l_inactive_str, 0, -1);
    if (l_net_item->exceptions)
        for (uint32_t i = 1; i < l_net_item->exceptions[0]; ++i) {
            dap_string_append_printf(l_inactive_str, "CN-%u ", l_net_item->exceptions[i]);
        }
    json_object_object_add(l_ret, "exceptions", json_object_new_string(l_inactive_str->str));
    dap_string_free(l_inactive_str, true);
    return l_ret;
}

json_object *dap_chain_policy_json_collect(dap_chain_net_id_t a_net_id, uint32_t a_num)
{
    dap_chain_policy_activate_t *l_policy_activate = s_policy_activate_find(a_net_id, a_num);
    if (!l_policy_activate) {
        return NULL;
    }
    json_object *l_ret = json_object_new_object();
    json_object_object_add(l_ret, "num", json_object_new_uint64(l_policy_activate->num));
    if (l_policy_activate->ts_start) {
        char l_time[DAP_TIME_STR_SIZE] = {};
        dap_time_to_str_rfc822(l_time, DAP_TIME_STR_SIZE - 1, l_policy_activate->ts_start);
        json_object_object_add(l_ret, "ts_start", json_object_new_string(l_time));
    } else {
        json_object_object_add(l_ret, "ts_start", json_object_new_int(0));
    }
    json_object_object_add(l_ret, "block_start", json_object_new_uint64(l_policy_activate->block_start));
    if (l_policy_activate->block_start) {
        dap_chain_t *l_chain = dap_chain_find_by_id(a_net_id, l_policy_activate->chain_id);
        if (!l_chain) {
            json_object_object_add(l_ret, "chain", json_object_new_string("NULL"));
        } else {
            char l_chain_id[32] = { };
            snprintf(l_chain_id, sizeof(l_chain_id) - 1, "0x%016"DAP_UINT64_FORMAT_x, l_policy_activate->chain_id.uint64);
            json_object_object_add(l_ret, "chain", json_object_new_string(l_chain_id));
        }
    } else {
        json_object_object_add(l_ret, "chain", json_object_new_string(""));
    }
    json_object_object_add(l_ret, "description", json_object_new_string("WIKI"));
    return l_ret;
}