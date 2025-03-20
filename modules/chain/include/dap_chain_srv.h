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

#include "dap_config.h"
#include "dap_chain_common.h"
#include "dap_tsd.h"

// System services literlas
#define DAP_CHAIN_SRV_STAKE_POS_DELEGATE_LITERAL "PoS-delegate"
#define DAP_CHAIN_SRV_XCHANGE_LITERAL "eXchange"
#define DAP_CHAIN_SRV_VOTING_LITERAL "poll"

// Start service callback
typedef void * (*dap_chain_srv_callback_start_t)(dap_chain_net_id_t a_net_id, dap_config_t *a_config);
// Process service decree
typedef void (*dap_chain_srv_callback_decree_t)(dap_chain_net_id_t a_net_id, int a_decree_type, dap_tsd_t *a_params, size_t a_params_size);
// Purge service callback
typedef int (*dap_chain_srv_callback_purge_t)(dap_chain_net_id_t a_net_id, void *a_service_internal);
// Get fee service callback
typedef json_object * (*dap_chain_srv_callback_get_fee)(dap_chain_net_id_t a_net_id);
// Hardfork prepare service callback
typedef byte_t * (*dap_chain_srv_callback_hardfork_prepare_t)(dap_chain_net_id_t a_net_id, uint64_t *a_state_size, uint32_t *a_state_count, void *a_service_internal);
// Hardfork data load service callback
typedef int (*dap_chain_srv_callback_hardfork_data_t)(dap_chain_net_id_t a_net_id, byte_t *a_state, uint64_t a_state_size, uint32_t a_state_count);

typedef struct dap_chain_static_srv_callbacks {
    // Init
    dap_chain_srv_callback_start_t start;
    // Decree processing
    dap_chain_srv_callback_decree_t decree;
    // Purge
    dap_chain_srv_callback_purge_t purge;
    // Get service fee
    dap_chain_srv_callback_get_fee get_fee_descr;
    // Hardfork prepare
    dap_chain_srv_callback_hardfork_prepare_t hardfork_prepare;
    // Hardfork data load
    dap_chain_srv_callback_hardfork_data_t hardfork_load;
    // And no more =)
} dap_chain_static_srv_callbacks_t;

typedef struct dap_chain_srv_hardfork_state {
    dap_chain_srv_uid_t uid;
    byte_t *data;
    uint64_t size;
    uint32_t count;
    struct dap_chain_srv_hardfork_state *prev, *next;
} dap_chain_srv_hardfork_state_t;

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

typedef struct dap_chain_srv_fee {
    // Sevice fee
    uint16_t type;
    uint256_t value;
    dap_chain_addr_t addr; // Addr collector
} dap_chain_srv_fee_t;

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

DAP_STATIC_INLINE int dap_chain_srv_init() { return 0; };
void dap_chain_srv_deinit();

int dap_chain_srv_add(dap_chain_srv_uid_t a_uid, const char *a_name, dap_chain_static_srv_callbacks_t *a_static_callbacks);
int dap_chain_srv_start(dap_chain_net_id_t a_net_id, const char *a_name, dap_config_t *a_config);
int dap_chain_srv_delete(dap_chain_srv_uid_t a_uid);
void *dap_chain_srv_get_internal(dap_chain_net_id_t a_net_id, dap_chain_srv_uid_t a_srv_id);
dap_chain_srv_uid_t dap_chain_srv_get_uid_by_name(const char *a_name);
size_t dap_chain_srv_count(dap_chain_net_id_t a_net_id);
dap_list_t *dap_chain_srv_list(dap_chain_net_id_t a_net_id);

int dap_chain_srv_purge(dap_chain_net_id_t a_net_id, dap_chain_srv_uid_t a_srv_uid);
int dap_chain_srv_purge_all(dap_chain_net_id_t a_net_id);
dap_chain_srv_hardfork_state_t *dap_chain_srv_hardfork_all(dap_chain_net_id_t a_net_id);
int dap_chain_srv_load_state(dap_chain_net_id_t a_net_id, dap_chain_srv_uid_t a_srv_uid, byte_t *a_state, uint64_t a_state_size, uint32_t a_state_count);
json_object *dap_chain_srv_get_fees(dap_chain_net_id_t a_net_id);
