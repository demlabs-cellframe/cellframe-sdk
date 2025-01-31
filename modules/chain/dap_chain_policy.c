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
#include "uthash.h"

static const char LOG_TAG[] = "dap_chain_policy";

typedef struct dap_chain_policy {
    uint16_t version;
    uint32_t num;
    uint64_t flags;
    uint64_t ts_start;
    uint64_t ts_stop;
    uint64_t block_start;
    uint64_t block_stop;
    uint64_t description_size;
    uint32_t policies_deactivate_count;
    char data[];
} dap_chain_policy_t;

struct policy_table_item {
    dap_chain_policy_t *policy;
    UT_hash_handle hh;
};

struct policy_net_list_item {
    dap_chain_net_id_t net_id;
    struct policy_table_item *policies;
};

static dap_list_t *s_net_list = NULL;


/**
 * @brief search net element in list bi id
 * @param a_net_id
 * @return pointer if find, NULL if not
 */
DAP_STATIC_INLINE struct policy_net_list_item *s_net_find(dap_chain_net_id_t a_net_id)
{
    for (dap_list_t *l_iter = dap_list_first(s_net_list); l_iter; l_iter = l_iter->next) {
        if ( ((struct policy_net_list_item *)(l_iter->data))->net_id.uint64 == a_net_id.uint64)
            return (struct policy_net_list_item *)(l_iter->data);
    }
    return NULL;
}

/**
 * @brief add new net to policies list
 * @param a_net_id
 * @return 0 if pass, other if error
 */
int dap_chain_policy_net_add(dap_chain_net_id_t a_net_id)
{
    dap_return_val_if_pass(!a_net_id.uint64, -1);
    if(s_net_find(a_net_id)) {
        log_it(L_ERROR, "Net with id %"DAP_UINT64_FORMAT_X" already added", a_net_id.uint64);
        return -2;
    }
    struct policy_net_list_item *l_new_item = DAP_NEW_Z_RET_VAL_IF_FAIL(struct policy_net_list_item, -3);
    s_net_list = dap_list_append(s_net_list, l_new_item);
    return 0;
}

/**
 * @brief init policies to all inited nets, should launch before nets loading
 * @return 0 if pass, other if error
 */
int dap_chain_policy_init()
{
    int l_ret = -1;
    for (dap_chain_net_t *l_net = dap_chain_net_iter_start(); l_net; l_net = dap_chain_net_iter_next(l_net)) {
        if( (l_ret = dap_chain_policy_net_add(l_net->pub.id)) )
            break;
    }
    return l_ret;
}
