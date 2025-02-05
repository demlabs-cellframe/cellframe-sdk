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

#define DAP_CHAIN_POLICY_FLAG_ACTIVATE_BY_TS            1
#define DAP_CHAIN_POLICY_FLAG_ACTIVATE_BY_BLOCK_NUM     (1 << 1)
#define DAP_CHAIN_POLICY_FLAG_ACTIVATE_BY_CONFIG        (1 << 2)

typedef struct dap_chain_policy {
    uint16_t version;
    uint32_t num;
    uint64_t flags;
    int64_t ts_start;
    int64_t ts_stop;
    uint64_t block_start;
    uint64_t block_stop;
    union {
        dap_chain_id_t chain_id;
        dap_chain_t *chain;
    } chain_union;
    uint64_t description_size;
    uint32_t policies_deactivate_count;
    char data[];
} dap_chain_policy_t;

int dap_chain_policy_net_add(uint64_t a_net_id);
int dap_chain_policy_net_remove(uint64_t a_net_id);
int dap_chain_policy_add(dap_chain_policy_t *a_policy, uint64_t a_net_id);
int dap_chain_policy_add_to_exception_list(uint32_t a_policy_num, uint64_t a_net_id);
uint32_t dap_chain_policy_get_last_num(uint64_t a_net_id);

DAP_STATIC_INLINE size_t dap_chain_policy_get_size(dap_chain_policy_t *a_policy)
{
    return a_policy ? a_policy->description_size + a_policy->policies_deactivate_count * sizeof(uint32_t) + sizeof(dap_chain_policy_t) : 0;
}