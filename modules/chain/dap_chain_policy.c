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
#include "uthash.h"

static const char LOG_TAG[] = "dap_chain_policy";

typedef struct dap_chain_policy {
    uint16_t version;
    uint32_t num;
    uint64_t flags;
    int64_t ts_start;
    int64_t ts_stop;
    uint64_t block_start;
    uint64_t block_stop;
    dap_chain_t *chain;
    uint64_t description_size;
    uint32_t policies_deactivate_count;
    char data[];
} dap_chain_policy_t;


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

/**
 * @brief add new net to policies list
 * @param a_net_id
 * @return 0 if pass, other if error
 */
static int s_net_add(uint64_t a_net_id)
{
    dap_return_val_if_pass(!a_net_id, -1);
    if(s_net_find(a_net_id)) {
        log_it(L_ERROR, "Net with id %"DAP_UINT64_FORMAT_X" already added", a_net_id);
        return -2;
    }
    struct policy_net_list_item *l_new_item = DAP_NEW_Z_RET_VAL_IF_FAIL(struct policy_net_list_item, -3);
    s_net_list = dap_list_append(s_net_list, l_new_item);
    return 0;
}

DAP_STATIC_INLINE int s_policy_num_compare(dap_list_t  *a_list1, dap_list_t  *a_list2)
{
    return ((dap_chain_policy_t *)(a_list1->data))->num == ((dap_chain_policy_t *)(a_list2->data))->num ? 0 :
        ((dap_chain_policy_t *)(a_list1->data))->num > ((dap_chain_policy_t *)(a_list2->data))->num ? 1 : -1;
}

/**
 * @brief init policies to all inited nets, should launch before nets loading
 * @return 0 if pass, other if error
 */
int dap_chain_policy_init()
{
    int l_ret = -1;
    // for (dap_chain_net_t *l_net = dap_chain_net_iter_start(); l_net; l_net = dap_chain_net_iter_next(l_net)) {
    //     if( (l_ret = s_net_add(l_net->pub.id)) )
    //         break;
    // }
    return l_ret;
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
    dap_chain_policy_t *l_policy_item = dap_list_find(l_net_item->policies, &l_to_search, s_policy_num_compare);
    if (!l_policy_item) {
        log_it(L_ERROR, "Can't find CN-%d in net %"DAP_UINT64_FORMAT_X, a_net_id);
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
