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
#include "dap_json.h"

#define LOG_TAG "dap_chain_policy"

#define DAP_CHAIN_POLICY_VERSION                1

typedef struct dap_chain_policy_deactivate {
    uint32_t count;
    uint32_t nums[];
} DAP_ALIGN_PACKED dap_chain_policy_deactivate_t;

typedef struct dap_chain_policy_activate {
    uint32_t num;
    dap_time_t ts_start;
    uint64_t block_start;
    dap_chain_id_t chain_id;
    uint16_t generation;
} DAP_ALIGN_PACKED dap_chain_policy_activate_t;

struct policy_activate_table {
    dap_chain_policy_activate_t *policy;
    UT_hash_handle hh;
};

struct policy_deactivate_table {
    uint32_t num;
    UT_hash_handle hh;
};

struct net_policy_item {
    dap_chain_net_id_t net_id;
    uint32_t last_num;
    uint32_t *exceptions;  // [0] - exceptions count
    struct policy_activate_table *activate;
    struct policy_deactivate_table *deactivate;
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
    HASH_FIND(hh, s_net_policy_items, &a_net_id, sizeof(a_net_id), l_net_item);
    return l_net_item;
}


DAP_STATIC_INLINE dap_chain_policy_activate_t *s_policy_activate_find(dap_chain_net_id_t a_net_id, uint32_t a_num)
{
    struct net_policy_item *l_net_item = s_net_item_find(a_net_id);
    if (!l_net_item) {
        return NULL;
    }
    struct policy_activate_table *l_ret = NULL;
    HASH_FIND_BYHASHVALUE(hh, l_net_item->activate, &a_num, sizeof(a_num), a_num, l_ret);
    return l_ret ? l_ret->policy : NULL;
}

DAP_STATIC_INLINE void s_net_item_purge(struct net_policy_item *a_net_item)
{
    dap_return_if_pass(!a_net_item);
    struct policy_activate_table
        *l_temp_activate = NULL,
        *l_current_activate = NULL;
    HASH_ITER(hh, a_net_item->activate, l_current_activate, l_temp_activate) {
        HASH_DEL(a_net_item->activate, l_current_activate);
        DAP_DELETE(l_current_activate);
    }
    struct policy_deactivate_table
        *l_temp_deactivate = NULL,
        *l_current_deactivate = NULL;
    HASH_ITER(hh, a_net_item->deactivate, l_current_deactivate, l_temp_deactivate) {
        HASH_DEL(a_net_item->deactivate, l_current_deactivate);
        DAP_DELETE(l_current_deactivate);
    }
}

DAP_STATIC_INLINE bool s_policy_is_cond(dap_chain_policy_activate_t *a_policy)
{
    return a_policy->block_start || a_policy->ts_start;
}

DAP_STATIC_INLINE bool s_policy_in_exceptions_list(struct net_policy_item *a_net_item, uint32_t a_num)
{
    if (a_net_item && a_net_item->exceptions)
        for (uint32_t i = 0; i < a_net_item->exceptions[0]; ++i) {
            if (a_net_item->exceptions[i + 1] == a_num)
                return true;
        }
    return false;
}

DAP_STATIC_INLINE struct policy_deactivate_table *s_policy_find_in_deactivate_table(struct net_policy_item *a_net_item, uint32_t a_num)
{
    struct policy_deactivate_table *l_find = NULL;
    HASH_FIND_BYHASHVALUE(hh, a_net_item->deactivate, &a_num, sizeof(a_num), a_num, l_find);
    return l_find;
}

DAP_STATIC_INLINE bool s_policy_is_deactivated(struct net_policy_item *a_net_item, uint32_t a_num)
{
    return s_policy_in_exceptions_list(a_net_item, a_num) || s_policy_find_in_deactivate_table(a_net_item, a_num);
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


static struct net_policy_item *s_net_purge(dap_chain_net_id_t a_net_id)
{
    dap_return_val_if_pass(!a_net_id.uint64, NULL);
    struct net_policy_item *l_net_item = s_net_item_find(a_net_id);
    if (!l_net_item) {
        log_it(L_ERROR, "Can't find net %"DAP_UINT64_FORMAT_X" in policy list", a_net_id.uint64);
        return NULL;
    }
    s_net_item_purge(l_net_item);
    return l_net_item;
}

DAP_INLINE void dap_chain_policy_net_purge(dap_chain_net_id_t a_net_id)
{
    s_net_purge(a_net_id);
}

/**
 * @brief init policy commands
 * @return 0 if pass, other if error
 */
int dap_chain_policy_init()
{
    return 0;
}


void dap_chain_policy_net_remove(dap_chain_net_id_t a_net_id)
{
    struct net_policy_item *l_net_item = s_net_purge(a_net_id);
    if (l_net_item)
        HASH_DEL(s_net_policy_items, l_net_item);
    DAP_DELETE(l_net_item);
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
        s_net_item_purge(l_current);
        DAP_DELETE(l_current);
    }
}

dap_chain_policy_t *dap_chain_policy_create_activate(uint32_t a_num, int64_t ts_start, uint64_t a_block_start, dap_chain_id_t a_chain_id, uint16_t a_generation)
{
    dap_return_val_if_pass(!a_num, NULL);
    dap_chain_policy_t *l_ret = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_policy_t, sizeof(dap_chain_policy_t) + sizeof(dap_chain_policy_activate_t), NULL);
    l_ret->version = DAP_CHAIN_POLICY_VERSION;
    l_ret->flags = DAP_FLAG_ADD(l_ret->flags, DAP_CHAIN_POLICY_FLAG_ACTIVATE);
    l_ret->data_size = sizeof(dap_chain_policy_activate_t);
    dap_chain_policy_activate_t *l_activate = (dap_chain_policy_activate_t *)l_ret->data;
    l_activate->num = a_num;
    l_activate->ts_start = ts_start;
    l_activate->block_start = a_block_start;
    l_activate->chain_id.uint64 = a_chain_id.uint64;
    l_activate->generation = a_generation;
    return l_ret;
}

dap_chain_policy_t *dap_chain_policy_create_deactivate(char **a_nums, uint32_t a_count)
{
    dap_return_val_if_pass(!a_nums || !a_count, NULL);
    size_t l_data_size = sizeof(dap_chain_policy_deactivate_t) + sizeof(uint32_t) * a_count;
    dap_chain_policy_t *l_ret = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_policy_t, l_data_size + sizeof(dap_chain_policy_t), NULL);
    l_ret->version = DAP_CHAIN_POLICY_VERSION;
    l_ret->data_size = l_data_size;
    dap_chain_policy_deactivate_t *l_deactivate = (dap_chain_policy_deactivate_t *)l_ret->data;
    l_deactivate->count = a_count;
    for (uint32_t i = 0; i < l_deactivate->count; ++i) {
        l_deactivate->nums[i] = strtoull(a_nums[i], NULL, 10);
    }
    return l_ret;
}

/**
 * @brief add new net to policies list
 * @param a_net_id
 * @return 0 if pass, other if error
 */
int dap_chain_policy_net_add(dap_chain_net_id_t a_net_id, dap_config_t *a_net_cfg)
{
    dap_return_val_if_pass(!a_net_id.uint64, -1);
    if(s_net_item_find(a_net_id)) {
        log_it(L_ERROR, "Net with id %"DAP_UINT64_FORMAT_X" already added", a_net_id.uint64);
        return -2;
    }
    struct net_policy_item *l_new_item = DAP_NEW_Z_RET_VAL_IF_FAIL(struct net_policy_item, -3);
    l_new_item->net_id = a_net_id;
    l_new_item->last_num = dap_config_get_item_uint32(a_net_cfg, "policy", "activate");
    HASH_ADD(hh, s_net_policy_items, net_id, sizeof(l_new_item->net_id), l_new_item);
    uint16_t l_policy_count = 0;
    const char **l_policy_str = dap_config_get_array_str(a_net_cfg, "policy", "deactivate", &l_policy_count);
    if (l_policy_count && l_policy_str) {
        l_new_item->exceptions = DAP_NEW_Z_COUNT_RET_VAL_IF_FAIL(uint32_t, l_policy_count + 1, -4);
        l_new_item->exceptions[0] = l_policy_count;
        for (uint32_t i = 0; i < l_policy_count; ++i) {
            l_new_item->exceptions[i + 1] = strtoul(l_policy_str[i], NULL, 10);
        }
    }
    return 0;
}

/**
 * @brief add new policy
 * @param a_policy_num
 * @param a_net_id net id
 * @return 0 if pass, other if error
 */
int dap_chain_policy_apply(dap_chain_policy_t *a_policy, dap_chain_net_id_t a_net_id)
{
    dap_return_val_if_pass(!a_policy || !a_policy->data_size, -1);

    struct net_policy_item *l_net_item = s_net_item_find(a_net_id);
    if (!l_net_item) {
        log_it(L_ERROR, "Can't find net %"DAP_UINT64_FORMAT_X" in policy list", a_net_id.uint64);
        return -3;
    }
    if (DAP_FLAG_CHECK(a_policy->flags, DAP_CHAIN_POLICY_FLAG_ACTIVATE)) {
        dap_chain_policy_activate_t *l_to_add = (dap_chain_policy_activate_t *)a_policy->data;
        struct policy_activate_table *l_item_to_add = NULL;
        HASH_FIND_BYHASHVALUE(hh, l_net_item->activate, &l_to_add->num, sizeof(l_to_add->num), l_to_add->num, l_item_to_add);
        if (l_item_to_add) {
            log_it(L_ERROR, "CN-%u already added to net %"DAP_UINT64_FORMAT_X, l_to_add->num, a_net_id.uint64);
            return -4;
        }
        l_item_to_add = DAP_NEW_Z_RET_VAL_IF_FAIL(struct policy_activate_table, -5);
        l_item_to_add->policy = l_to_add;
        HASH_ADD_BYHASHVALUE(hh, l_net_item->activate, policy->num, sizeof(l_item_to_add->policy->num), l_item_to_add->policy->num, l_item_to_add);
        // remove from deactivate table
        struct policy_deactivate_table *l_item_to_del = s_policy_find_in_deactivate_table(l_net_item, l_item_to_add->policy->num);
        if (l_item_to_del) {
            HASH_DEL(l_net_item->deactivate, l_item_to_del);
            DAP_DELETE(l_item_to_del);
        }
        if (!s_policy_is_cond(l_to_add) || s_policy_cond_activated(l_net_item->net_id, l_to_add))
            l_net_item->last_num = dap_max(l_to_add->num, l_net_item->last_num);
    } else {
        dap_chain_policy_deactivate_t *l_to_deactivate = (dap_chain_policy_deactivate_t *)a_policy->data;
        for (uint32_t i = 0; i < l_to_deactivate->count; ++i) {
            struct policy_deactivate_table *l_item_to_add = NULL;
            HASH_FIND_BYHASHVALUE(hh, l_net_item->deactivate, &l_to_deactivate->nums[i], sizeof(l_to_deactivate->nums[i]), l_to_deactivate->nums[i], l_item_to_add);
            if (l_item_to_add) {
                log_it(L_ERROR, "CN-%u already added to deactivate list in net %"DAP_UINT64_FORMAT_X, l_to_deactivate->nums[i], a_net_id.uint64);
                continue;
            }
            l_item_to_add = DAP_NEW_Z_RET_VAL_IF_FAIL(struct policy_deactivate_table, -5);
            l_item_to_add->num = l_to_deactivate->nums[i];
            HASH_ADD_BYHASHVALUE(hh, l_net_item->deactivate, num, sizeof(l_item_to_add->num), l_item_to_add->num, l_item_to_add);
            // remove from activate table
            struct policy_activate_table *l_item_to_del = NULL;
            HASH_FIND_BYHASHVALUE(hh, l_net_item->activate, &l_to_deactivate->nums[i], sizeof(l_to_deactivate->nums[i]), l_to_deactivate->nums[i], l_item_to_del);
            if (l_item_to_del) {
                HASH_DEL(l_net_item->activate, l_item_to_del);
                DAP_DELETE(l_item_to_del);
            }
        }
    }
    return 0;
}

/**
 * @brief add new policy
 * @param a_policy_num
 * @param a_net_id net id
 * @return 0 if pass, other if error
 */
void dap_chain_policy_update_last_num(dap_chain_net_id_t a_net_id, uint32_t a_num)
{
    struct net_policy_item *l_net_item = s_net_item_find(a_net_id);
    if (!l_net_item) {
        log_it(L_ERROR, "Can't find net %"DAP_UINT64_FORMAT_X" in policy list", a_net_id.uint64);
        return;
    }
    l_net_item->last_num = dap_max(a_num, l_net_item->last_num);
    return;
}

DAP_INLINE bool dap_chain_policy_is_exist(dap_chain_net_id_t a_net_id, uint32_t a_num)
{
   return !!s_policy_activate_find(a_net_id, a_num);
}

/**
 * @brief check policy activation
 * @param a_policy_num
 * @param a_net_id net id
 * @return true if yes, false if no
 */
bool dap_chain_policy_is_activated(dap_chain_net_id_t a_net_id, uint32_t a_policy_num)
{
    bool l_ret = false;
    struct net_policy_item *l_net_item = s_net_item_find(a_net_id);
    dap_return_val_if_pass(!l_net_item, l_ret);
    // exception list check
    if (s_policy_is_deactivated(l_net_item, a_policy_num))
        return l_ret;
    // seach politics to condition check
    struct policy_activate_table *l_policy_activate = NULL;
    HASH_FIND_BYHASHVALUE(hh, l_net_item->activate, &a_policy_num, sizeof(a_policy_num), a_policy_num, l_policy_activate);
    if (l_policy_activate && s_policy_is_cond(l_policy_activate->policy)) {
        l_ret |= s_policy_cond_activated(a_net_id, l_policy_activate->policy);
        if (l_ret && l_net_item->last_num < a_policy_num)
            l_net_item->last_num = dap_max(a_policy_num, l_net_item->last_num);
        return l_ret;
    }
    // cumulative return
    l_ret |= a_policy_num <= l_net_item->last_num;
    if (!l_ret) {
        struct policy_activate_table
        *l_temp = NULL,
        *l_current = NULL;
        HASH_ITER(hh, l_net_item->activate, l_current, l_temp) {
            if (s_policy_is_cond(l_current->policy) && s_policy_cond_activated(l_net_item->net_id, l_current->policy) && l_current->policy->num > l_net_item->last_num)
                l_net_item->last_num = l_current->policy->num;
        }
        l_ret |= a_policy_num <= l_net_item->last_num;
    }
    return l_ret;
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
    return l_net_item->last_num;
}


dap_json_t *dap_chain_policy_list(dap_chain_net_id_t a_net_id, int a_version)
{
    struct net_policy_item *l_net_item = s_net_item_find(a_net_id);
    dap_return_val_if_pass(!l_net_item, NULL);
    dap_json_t *l_ret = dap_json_object_new();

    dap_string_t *l_active_str = dap_string_new("");
    dap_string_t *l_inactive_str = dap_string_new("");
    if (l_net_item->last_num)
        dap_string_append_printf(l_active_str, "%s CN-%u ", s_policy_is_deactivated(l_net_item, l_net_item->last_num) ? "<" : "<=", l_net_item->last_num);
    dap_json_object_add_string(l_ret, a_version == 1 ? "cumulative active" : "cumulative_active", l_active_str->str);
    dap_string_erase(l_active_str, 0, -1);
    struct policy_activate_table
        *l_temp = NULL,
        *l_current = NULL;
    HASH_ITER(hh, l_net_item->activate, l_current, l_temp) {
        if (s_policy_is_cond(l_current->policy)) {
            if (s_policy_cond_activated(l_net_item->net_id, l_current->policy))
                dap_string_append_printf(l_active_str, "CN-%u ", l_current->policy->num);
            else
                dap_string_append_printf(l_inactive_str, "CN-%u ", l_current->policy->num);
        }
    }
    dap_json_object_add_string(l_ret, a_version == 1 ? "conditional active" : "conditional_active", l_active_str->str);
    dap_json_object_add_string(l_ret, a_version == 1 ? "conditional inactive" : "conditional_inactive", l_inactive_str->str);
    
    dap_string_free(l_active_str, true);
    dap_string_erase(l_inactive_str, 0, -1);
    // add decree deactvated info
    struct policy_deactivate_table
        *l_temp_deactivate = NULL,
        *l_current_deactivate = NULL;
    HASH_ITER(hh, l_net_item->deactivate, l_current_deactivate, l_temp_deactivate) {
        dap_string_append_printf(l_inactive_str, "CN-%u ", l_current_deactivate->num);
    }
    dap_json_object_add_string(l_ret, "deactivated", l_inactive_str->str);
    // add config deactvated info
    dap_string_erase(l_inactive_str, 0, -1);
    if (l_net_item->exceptions)
        for (uint32_t i = 0; i < l_net_item->exceptions[0]; ++i) {
            dap_string_append_printf(l_inactive_str, "CN-%u ", l_net_item->exceptions[i + 1]);
        }
    dap_json_object_add_string(l_ret, "exceptions", l_inactive_str->str);
    dap_string_free(l_inactive_str, true);
    return l_ret;
}

dap_json_t *dap_chain_policy_activate_json_collect(dap_chain_net_id_t a_net_id, uint32_t a_num)
{
    dap_chain_policy_activate_t *l_policy_activate = s_policy_activate_find(a_net_id, a_num);
    if (!l_policy_activate) {
        return NULL;
    }
    dap_json_t *l_ret = dap_json_object_new();
    dap_json_object_add_uint64(l_ret, "num", l_policy_activate->num);
    if (l_policy_activate->ts_start) {
        char l_time[DAP_TIME_STR_SIZE] = {};
        dap_time_to_str_rfc822(l_time, DAP_TIME_STR_SIZE - 1, l_policy_activate->ts_start);
        dap_json_object_add(l_ret, "ts_start", dap_json_object_new_string(l_time));
    } else {
        dap_json_object_add(l_ret, "ts_start", dap_json_object_new_int(0));
    }
    dap_json_object_add(l_ret, "block_start", dap_json_object_new_uint64(l_policy_activate->block_start));
    if (l_policy_activate->block_start) {
        dap_chain_t *l_chain = dap_chain_find_by_id(a_net_id, l_policy_activate->chain_id);
        if (!l_chain) {
            dap_json_object_add(l_ret, "chain", dap_json_object_new_string("NULL"));
        } else {
            char l_chain_id[32] = { };
            snprintf(l_chain_id, sizeof(l_chain_id) - 1, "0x%016"DAP_UINT64_FORMAT_x, l_policy_activate->chain_id.uint64);
            dap_json_object_add(l_ret, "chain", dap_json_object_new_string(l_chain_id));
        }
    } else {
        dap_json_object_add(l_ret, "chain", dap_json_object_new_string(""));
    }
    dap_json_object_add(l_ret, "description", dap_json_object_new_string("WIKI"));
    return l_ret;
}

dap_json_t *dap_chain_policy_json_collect(dap_chain_policy_t *a_policy)
{
    dap_return_val_if_pass(!a_policy, NULL);
    dap_json_t *l_ret = dap_json_object_new();

    dap_json_object_add(l_ret, "version", dap_json_object_new_uint64(a_policy->version));
    dap_json_object_add(l_ret, "type", dap_json_object_new_string(dap_chain_policy_to_str(a_policy)));
    if (DAP_FLAG_CHECK(a_policy->flags, DAP_CHAIN_POLICY_FLAG_ACTIVATE)) {
        dap_chain_policy_activate_t *l_policy_activate = (dap_chain_policy_activate_t *)a_policy->data;
        dap_json_object_add(l_ret, "num", dap_json_object_new_uint64(l_policy_activate->num));
        if (l_policy_activate->ts_start) {
            char l_time[DAP_TIME_STR_SIZE] = {};
            dap_time_to_str_rfc822(l_time, DAP_TIME_STR_SIZE - 1, l_policy_activate->ts_start);
            dap_json_object_add(l_ret, "ts_start", dap_json_object_new_string(l_time));
        } else {
            dap_json_object_add(l_ret, "ts_start", dap_json_object_new_int(0));
        }
        dap_json_object_add(l_ret, "block_start", dap_json_object_new_uint64(l_policy_activate->block_start));
        if (l_policy_activate->block_start) {
                char l_chain_id[32] = { };
                snprintf(l_chain_id, sizeof(l_chain_id) - 1, "0x%016"DAP_UINT64_FORMAT_x, l_policy_activate->chain_id.uint64);
                dap_json_object_add(l_ret, "chain", dap_json_object_new_string(l_chain_id));
        } else {
            dap_json_object_add(l_ret, "chain", dap_json_object_new_string(""));
        }
        dap_json_object_add(l_ret, "description", dap_json_object_new_string("WIKI"));
    } else {
        dap_chain_policy_deactivate_t *l_policy_deactivate = (dap_chain_policy_deactivate_t *)a_policy->data;
        if (l_policy_deactivate->count) {
            dap_string_t *l_nums_list = dap_string_sized_new(l_policy_deactivate->count * (sizeof(uint32_t) + 4));
            for (size_t i = 0; i < l_policy_deactivate->count; ++i) {
                dap_string_append_printf(l_nums_list, "CN-%u ", l_policy_deactivate->nums[i]);
            }
            dap_json_object_add(l_ret, "deactivate", dap_json_object_new_string(l_nums_list->str));
            dap_string_free(l_nums_list, true);
        } else {
            dap_json_object_add(l_ret, "deactivate", dap_json_object_new_string(""));
        }
    }
    return l_ret;
}