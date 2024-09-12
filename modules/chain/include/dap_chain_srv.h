/*
* Authors:
* Roman Khlopkov <roman.khlopkov@demlabs.net>
* Cellframe       https://cellframe.net
* DeM Labs Inc.   https://demlabs.net
* Copyright  (c) 2017-2024
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

#include "dap_chain.h"

// Process service decree
typedef void (*dap_chain_net_srv_callback_decree_t)(dap_chain_t *a_chain, int a_decree_type, ...);
// Purge service callback
typedef int (*dap_chain_net_srv_callback_purge_t)(void);
// Get fee service callback
typedef json_object * (*dap_chain_net_srv_callback_get_fee)(void);
// Hardfork service callback
typedef int (*dap_chain_net_srv_callback_hardfork_t)(void);

typedef struct dap_chain_static_srv_callbacks {
    // Decree processing
    dap_chain_net_srv_callback_decree_t decree;
    // Purge
    dap_chain_net_srv_callback_purge_t purge;
    // Get service fee
    dap_chain_net_srv_callback_get_fee get_fee_descr;
    // Hardfork
    dap_chain_net_srv_callback_hardfork_t hardfork;
} dap_chain_static_srv_callbacks_t;

// Fees section
typedef enum dap_chain_srv_fee_tsd_type {
    TSD_FEE = 0x0001,
    TSD_FEE_TYPE,
    TSD_FEE_ADDR
} dap_chain_srv_fee_tsd_type_t;

typedef enum dap_chain_srv_fee_type {
    SERVICE_FEE_OWN_FIXED = 0x1,
    SERVICE_FEE_OWN_PERCENT,
    SERVICE_FEE_NATIVE_FIXED,
    SERIVCE_FEE_NATIVE_PERCENT
} dap_chain_srv_fee_type_t;

typedef struct dap_chain_srv_fee_item {
    // Sevice fee
    uint16_t fee_type;
    uint256_t fee;
    dap_chain_addr_t fee_addr; // Addr collector

    UT_hash_handle hh;
} dap_chain_srv_fee_item_t;

DAP_STATIC_INLINE const char *dap_chain_srv_fee_type_to_str(dap_chain_srv_fee_type_t a_fee_type)
{
    switch (a_fee_type) {
    case SERVICE_FEE_OWN_FIXED: return "SERVICE_FEE_OWN_FIXED";
    case SERVICE_FEE_OWN_PERCENT: return "SERVICE_FEE_OWN_PERCENT";
    case SERVICE_FEE_NATIVE_FIXED: return "SERVICE_FEE_NATIVE_FIXED";
    case SERIVCE_FEE_NATIVE_PERCENT: return "SERIVCE_FEE_NATIVE_PERCENT";
    default: return "UNKNOWN";
    }
}

int dap_chain_srv_add(dap_chain_net_id_t a_net_id, dap_chain_net_srv_uid_t a_uid, const char *a_name,
                      dap_chain_static_srv_callbacks_t *a_static_callbacks, void *a_highlevel);

void dap_chain_srv_del_all(void);

void *dap_chain_srv_get(dap_chain_net_id_t a_net_id, dap_chain_net_srv_uid_t a_srv_id);
void *dap_chain_srv_get_by_name(dap_chain_net_id_t a_net_id, const char *a_name);
size_t dap_chain_srv_count(void);
const dap_chain_net_srv_uid_t *dap_chain_srv_list(void);