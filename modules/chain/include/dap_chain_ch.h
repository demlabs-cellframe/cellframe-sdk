/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Ltd   https://demlabs.net
 * CellFrame SDK https://gitlab.demlabs.net/cellframe/cellframe-sdk
 * Copyright  (c) 2020
 * All rights reserved.

 This file is part of DapChain SDK the open source project

    DapChain SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DapChain SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
**/

#pragma once

#include <pthread.h>

#include "dap_chain_common.h"
#include "dap_chain.h"
#include "dap_list.h"
#include "dap_chain_ch_pkt.h"
#include "uthash.h"
#include "dap_global_db_cluster.h"

#define DAP_CHAIN_CH_ID 'C'

typedef enum dap_chain_ch_state {
    DAP_CHAIN_CH_STATE_IDLE = 0,
    DAP_CHAIN_CH_STATE_WAITING,
    DAP_CHAIN_CH_STATE_UPDATE_GLOBAL_DB_REMOTE, // Download GDB hashtable from remote
    DAP_CHAIN_CH_STATE_UPDATE_GLOBAL_DB, // Update GDB hashtable to remote
    DAP_CHAIN_CH_STATE_SYNC_GLOBAL_DB_REMOTE,
    DAP_CHAIN_CH_STATE_SYNC_GLOBAL_DB,
    DAP_CHAIN_CH_STATE_UPDATE_CHAINS_REMOTE, // Update chains hashtable from remote
    DAP_CHAIN_CH_STATE_UPDATE_CHAINS, // Update chains hashtable to remote
    DAP_CHAIN_CH_STATE_SYNC_CHAINS_REMOTE,
    DAP_CHAIN_CH_STATE_SYNC_CHAINS,
    DAP_CHAIN_CH_STATE_ERROR
} dap_chain_ch_state_t;

typedef enum dap_chain_ch_error_type {
    DAP_CHAIN_CH_ERROR_SYNC_REQUEST_ALREADY_IN_PROCESS,
    DAP_CHAIN_CH_ERROR_INCORRECT_SYNC_SEQUENCE,
    DAP_CHAIN_CH_ERROR_SYNC_TIMEOUT,
    DAP_CHAIN_CH_ERROR_CHAIN_PKT_DATA_SIZE,
    DAP_CHAIN_CH_ERROR_NET_INVALID_ID,
    DAP_CHAIN_CH_ERROR_CHAIN_NOT_FOUND,
    DAP_CHAIN_CH_ERROR_ATOM_NOT_FOUND,
    DAP_CHAIN_CH_ERROR_UNKNOWN_CHAIN_PKT_TYPE,
    DAP_CHAIN_CH_ERROR_NET_IS_OFFLINE,
    DAP_CHAIN_CH_ERROR_OUT_OF_MEMORY,
    DAP_CHAIN_CH_ERROR_INTERNAL,
// Legacy
    DAP_CHAIN_CH_ERROR_GLOBAL_DB_INTERNAL_NOT_SAVED,
    DAP_CHAIN_CH_ERROR_LEGACY_PKT_DATA_SIZE
} dap_chain_ch_error_type_t;

int dap_chain_ch_init(void);
void dap_chain_ch_deinit(void);

void dap_chain_ch_timer_start(dap_chain_ch_t *a_ch_chain);

void dap_stream_ch_write_error_unsafe(dap_stream_ch_t *a_ch, uint64_t a_net_id, uint64_t a_chain_id, uint64_t a_cell_id, dap_chain_ch_error_type_t a_error);
