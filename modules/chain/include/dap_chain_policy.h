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

#define DAP_CHAIN_POLICY_FLAG_ACTIVATE                      BIT(0)

#define DAP_CHAIN_POLICY_PUBLIC_KEY_HASH_SIGN_VALIDATORS    0x1
#define DAP_CHAIN_POLICY_OUT_STD_TIMELOCK_USE               0x2

typedef struct dap_chain_policy {
    uint16_t version;
    uint64_t flags;
    uint64_t data_size;
    uint8_t data[];
} DAP_ALIGN_PACKED dap_chain_policy_t;

int dap_chain_policy_init();
void dap_chain_policy_deinit();
dap_chain_policy_t *dap_chain_policy_create_activate(uint32_t a_num, int64_t ts_start, uint64_t a_block_start, dap_chain_id_t a_chain_id, uint16_t a_generation);
dap_chain_policy_t *dap_chain_policy_create_deactivate(char **a_nums, uint32_t a_count);
int dap_chain_policy_net_add(dap_chain_net_id_t a_net_id, dap_config_t *a_net_cfg);
void dap_chain_policy_net_purge(dap_chain_net_id_t a_net_id);
void dap_chain_policy_net_remove(dap_chain_net_id_t a_net_id);
int dap_chain_policy_apply(dap_chain_policy_t *a_policy, dap_chain_net_id_t a_net_id);
//TODO: put under rwlock and unify
void dap_chain_policy_update_last_num(dap_chain_net_id_t a_net_id, uint32_t a_num);
uint32_t dap_chain_policy_get_last_num(dap_chain_net_id_t a_net_id);
json_object *dap_chain_policy_activate_json_collect(dap_chain_net_id_t a_net_id, uint32_t a_num);
json_object *dap_chain_policy_json_collect(dap_chain_policy_t *a_policy);
json_object *dap_chain_policy_list(dap_chain_net_id_t a_net_id);
bool dap_chain_policy_is_exist(dap_chain_net_id_t a_net_id, uint32_t a_num);
bool dap_chain_policy_is_activated(dap_chain_net_id_t a_net_id, uint32_t a_policy_num);

DAP_STATIC_INLINE size_t dap_chain_policy_get_size(dap_chain_policy_t *a_policy)
{
    return a_policy ? sizeof(dap_chain_policy_t) + a_policy->data_size : 0;
}

DAP_STATIC_INLINE const char *dap_chain_policy_to_str(dap_chain_policy_t *a_policy)
{
    return a_policy ? DAP_FLAG_CHECK(a_policy->flags, DAP_CHAIN_POLICY_FLAG_ACTIVATE)
        ? "DAP_CHAIN_POLICY_ACTIVATE" : "DAP_CHAIN_POLICY_DEACTIVATE"
    : "<null>";
}
