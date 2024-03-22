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

#define DAP_SYNC_TICKS_PER_SECOND           10

typedef enum dap_chain_ch_state {
    DAP_CHAIN_CH_STATE_IDLE = 0,
    DAP_CHAIN_CH_STATE_WAITING,
    DAP_CHAIN_CH_STATE_UPDATE_GLOBAL_DB_REMOTE, // Downloadn GDB hashtable from remote
    DAP_CHAIN_CH_STATE_UPDATE_GLOBAL_DB, // Update GDB hashtable to remote
    DAP_CHAIN_CH_STATE_SYNC_GLOBAL_DB,
    DAP_CHAIN_CH_STATE_UPDATE_CHAINS_REMOTE, // Update chains hashtable from remote
    DAP_CHAIN_CH_STATE_UPDATE_CHAINS, // Update chains hashtable to remote
    DAP_CHAIN_CH_STATE_SYNC_CHAINS,
    DAP_CHAIN_CH_STATE_ERROR
} dap_chain_ch_state_t;

typedef enum dap_chain_ch_error_type {
    DAP_CHAIN_CH_ERROR_SYNC_REQUEST_ALREADY_IN_PROCESS,
    DAP_CHAIN_CH_ERROR_INCORRECT_SYNC_SEQUENCE,
    DAP_CHAIN_CH_ERROR_CHAIN_PKT_DATA_SIZE,
    DAP_CHAIN_CH_ERROR_NET_INVALID_ID,
    DAP_CHAIN_CH_ERROR_CHAIN_NOT_FOUND,
    DAP_CHAIN_CH_ERROR_ATOM_NOT_FOUND,
    DAP_CHAIN_CH_ERROR_UNKNOWN_CHAIN_PKT_TYPE,
    DAP_CHAIN_CH_ERROR_GLOBAL_DB_INTERNAL_NOT_SAVED
} dap_chain_ch_error_type_t;

typedef struct dap_chain_ch dap_chain_ch_t;
typedef void (*dap_chain_ch_callback_packet_t)(dap_chain_ch_t*, uint8_t a_pkt_type,
                                                      dap_chain_ch_pkt_t *a_pkt, size_t a_pkt_data_size,
                                                      void * a_arg);
typedef struct dap_chain_pkt_item {
    uint64_t pkt_data_size;
    byte_t *pkt_data;
} dap_chain_pkt_item_t;

typedef struct dap_chain_ch_hash_item{
    dap_hash_fast_t hash;
    uint32_t size;
    UT_hash_handle hh;
} dap_chain_ch_hash_item_t;


typedef struct dap_chain_ch {
    void *_inheritor;
    dap_timerfd_t *sync_timer;
    void *sync_context;

    // Legacy section //
    int state;

    uint64_t stats_request_atoms_processed;
    uint64_t stats_request_gdb_processed;

    dap_chain_ch_hash_item_t * remote_atoms; // Remote atoms
    dap_chain_ch_hash_item_t * remote_gdbs; // Remote gdbs

    // request section
    dap_chain_atom_iter_t *request_atom_iter;
    //dap_db_log_list_t *request_db_log; // list of global db records
    dap_chain_ch_sync_request_t request;
    dap_chain_ch_pkt_hdr_t request_hdr;
    dap_list_t *request_db_iter;

    uint32_t timer_shots;
    dap_timerfd_t *activity_timer;
    int sent_breaks;

    dap_chain_ch_callback_packet_t callback_notify_packet_out;
    dap_chain_ch_callback_packet_t callback_notify_packet_in;
    void *callback_notify_arg;
} dap_chain_ch_t;

#define DAP_CHAIN_CH(a) ((dap_chain_ch_t *) ((a)->internal) )
#define DAP_STREAM_CH(a) ((dap_stream_ch_t *)((a)->_inheritor))
#define DAP_CHAIN_PKT_EXPECT_SIZE 7168
#define DAP_CHAIN_CH_ID 'C'

int dap_chain_ch_init(void);
void dap_chain_ch_deinit(void);

void dap_chain_ch_timer_start(dap_chain_ch_t *a_ch_chain);
void dap_chain_ch_reset_unsafe(dap_chain_ch_t *a_ch_chain);
