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

#define DAP_CHAIN_POLICY_FLAG_ACTIVATE_BY_TS            1
#define DAP_CHAIN_POLICY_FLAG_ACTIVATE_BY_BLOCK_NUM     (1 << 1)
#define DAP_CHAIN_POLICY_FLAG_ACTIVATE_BY_CONFIG        (1 << 2)

#define DAP_CHAIN_POLICY_PUBLIC_KEY_HASH_SIGN_VALIDATORS    0x1
#define DAP_CHAIN_POLICY_OUT_EXT_USE_ENSURE                 0x2

typedef struct dap_chain_policy {
    uint16_t version;
    struct {
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
    } activate;
    struct {
        uint32_t count;
        uint32_t nums[];
    } deactivate;
} dap_chain_policy_t;

int dap_chain_policy_init();
int dap_chain_policy_net_add(uint64_t a_net_id);
int dap_chain_policy_net_remove(uint64_t a_net_id);
int dap_chain_policy_add(dap_chain_policy_t *a_policy, uint64_t a_net_id);
int dap_chain_policy_add_to_exception_list(uint32_t a_policy_num, uint64_t a_net_id);
uint32_t dap_chain_policy_get_last_num(uint64_t a_net_id);
dap_chain_policy_t *dap_chain_policy_find(uint32_t a_policy_num, uint64_t a_net_id);
json_object *dap_chain_policy_json_collect(dap_chain_policy_t *a_policy);
json_object *dap_chain_policy_list(uint64_t a_net_id);
bool dap_chain_policy_activated(uint32_t a_policy_num, uint64_t a_net_id);

DAP_STATIC_INLINE size_t dap_chain_policy_get_size(dap_chain_policy_t *a_policy)
{
    return a_policy ? a_policy->deactivate.count * sizeof(uint32_t) + sizeof(dap_chain_policy_t) : 0;
}
