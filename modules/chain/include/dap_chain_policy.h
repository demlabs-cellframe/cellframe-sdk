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

#pragma once

#include "dap_common.h"
#include "dap_chain.h"

#define DAP_CHAIN_POLICY_VERSION                1

#define DAP_CHAIN_POLICY_FLAG_ACTIVATE_BY_TS            BIT(0)
#define DAP_CHAIN_POLICY_FLAG_ACTIVATE_BY_BLOCK_NUM     BIT(1)
#define DAP_CHAIN_POLICY_FLAG_ACTIVATE_BY_CONFIG        BIT(2)

#define DAP_CHAIN_POLICY_PUBLIC_KEY_HASH_SIGN_VALIDATORS    0x1
#define DAP_CHAIN_POLICY_OUT_STD_TIMELOCK_USE               0x2

typedef enum {
    DAP_CHAIN_POLICY_DEACTIVATE = 0,
    DAP_CHAIN_POLICY_ACTIVATE
} dap_chain_policy_type_t;

typedef struct dap_chain_policy_deactivate {
    uint32_t count;
    uint32_t nums[];
} DAP_ALIGN_PACKED dap_chain_policy_deactivate_t;


typedef struct dap_chain_policy_activate {
    uint32_t num;
    int64_t ts_start;
    uint64_t block_start;
    union {
        dap_chain_id_t chain_id;
        dap_chain_t *chain;
    } chain_union;
    uint16_t generation;
} DAP_ALIGN_PACKED dap_chain_policy_activate_t;

typedef struct dap_chain_policy {
    uint16_t version;
    uint16_t type;
    uint64_t flags;
    uint64_t data_size;
    uint8_t data[];
} DAP_ALIGN_PACKED dap_chain_policy_t;

int dap_chain_policy_init();
void dap_chain_policy_deinit();
int dap_chain_policy_net_add(uint64_t a_net_id);
int dap_chain_policy_net_remove(uint64_t a_net_id);
int dap_chain_policy_add(dap_chain_policy_t *a_policy, uint64_t a_net_id);
int dap_chain_policy_add_to_exception_list(uint32_t a_policy_num, uint64_t a_net_id);
uint32_t dap_chain_policy_get_last_num(uint64_t a_net_id);
dap_chain_policy_t *dap_chain_policy_find(uint32_t a_policy_num, uint64_t a_net_id);
json_object *dap_chain_policy_json_collect(dap_chain_policy_t *a_policy);
json_object *dap_chain_policy_list(uint64_t a_net_id);
bool dap_chain_policy_activated(uint32_t a_policy_num, uint64_t a_net_id);

DAP_STATIC_INLINE size_t dap_chain_policy_deactivate_calc_size(size_t a_deactivate_count)
{
    return sizeof(dap_chain_policy_t) + sizeof(dap_chain_policy_deactivate_t) + sizeof(uint32_t) * a_deactivate_count;
}

DAP_STATIC_INLINE size_t dap_chain_policy_get_size(dap_chain_policy_t *a_policy)
{
    return a_policy ? sizeof(dap_chain_policy_t)  + a_policy->data_size : 0;
}

DAP_STATIC_INLINE const char *dap_chain_policy_to_str(dap_chain_policy_t *a_policy)
{
    if(!a_policy)
        return "NULL";
    switch (a_policy->type) {
        case DAP_CHAIN_POLICY_ACTIVATE: return ("DAP_CHAIN_POLICY_ACTIVATE");
        case DAP_CHAIN_POLICY_DEACTIVATE: return ("DAP_CHAIN_POLICY_DEACTIVATE");
        default: return ("UNKNOWN");
    }
}

/**
 * @brief check policy num
 * @param a_num
 * @return true if valid, fail if not
 */
DAP_STATIC_INLINE bool dap_chain_policy_num_is_valid(uint64_t a_num)
{
    uint32_t l_num = dap_maxval(l_num);
    return (a_num && a_num <= l_num);
}
