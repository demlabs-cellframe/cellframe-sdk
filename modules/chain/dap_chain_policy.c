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
#include "dap_list.h"
#include "uthash.h"

static const char LOG_TAG[] = "dap_chain_policy";

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
    return ((dap_chain_policy_t *)(a_list1->data))->num == ((dap_chain_policy_t *)(a_list2->data))->num ? 0 :
        ((dap_chain_policy_t *)(a_list1->data))->num > ((dap_chain_policy_t *)(a_list2->data))->num ? 1 : -1;
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
 * @brief init policies to all inited nets, should launch before nets loading
 * @return 0 if pass, other if error
 */
int dap_chain_policy_init()
{
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
        log_it(L_ERROR, "CN-%u already added to net %"DAP_UINT64_FORMAT_X, a_policy->num, a_net_id);
        return -3;
    }
    l_net_item->policies = dap_list_insert_sorted(l_net_item->policies, a_policy, s_policy_num_compare);
    for (size_t i = 0; i < a_policy->policies_deactivate_count; ++i) {
        uint32_t l_policy_num = *(((uint32_t *)(a_policy->data + a_policy->description_size)) + i);
        if (dap_list_find(l_net_item->exception_list, (const void *)l_policy_num, NULL)) {
            log_it(L_ERROR, "CN-%u already added to exception list net %"DAP_UINT64_FORMAT_X, l_policy_num, a_net_id);
            continue;
        }
        l_net_item->exception_list = dap_list_insert_sorted(l_net_item->exception_list, (const void *)l_policy_num, NULL);
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
 * @param a_net pointer to net
 * @return true if yes, false if no
 */
bool dap_chain_policy_activated(uint32_t a_policy_num, uint64_t a_net_id)
{
    bool l_ret = false;
    struct policy_net_list_item *l_net_item = s_net_find(a_net_id);
    dap_return_val_if_pass(!l_net_item, l_ret);
    if (l_net_item->last_num_policy < a_policy_num)
        return l_ret;
    if (dap_list_find(l_net_item->exception_list, (const void *)a_policy_num, NULL))
        return l_ret;
    dap_chain_policy_t l_to_search = {
        .num = a_policy_num
    };
    dap_chain_policy_t *l_policy_item = (dap_chain_policy_t *)(dap_list_find(l_net_item->policies, &l_to_search, s_policy_num_compare)->data);
    if (!l_policy_item) {
        log_it(L_ERROR, "Can't find CN-%u in net %"DAP_UINT64_FORMAT_X, a_policy_num, a_net_id);
        return l_ret;
    }
    if (DAP_CHECK_FLAG(l_policy_item->flags, DAP_CHAIN_POLICY_FLAG_ACTIVATE_BY_TS)) {
        time_t l_current_time = dap_time_now();
        if (l_current_time < l_policy_item->ts_start || (l_policy_item->ts_stop && l_current_time > l_policy_item->ts_stop))
            return l_ret;
    }
    if (DAP_CHECK_FLAG(l_policy_item->flags, DAP_CHAIN_POLICY_FLAG_ACTIVATE_BY_BLOCK_NUM)) {
        if (!l_policy_item->chain) {
            log_it(L_ERROR, "Chain is null in policy item with upped DAP_CHAIN_POLICY_FLAG_ACTIVATE_BY_BLOCK_NUM flag");
            return l_ret;
        }
        if ( l_policy_item->chain->atom_num_last < l_policy_item->block_start || (l_policy_item->block_stop && l_policy_item->chain->atom_num_last > l_policy_item->block_stop))
            return l_ret;
    }
}
