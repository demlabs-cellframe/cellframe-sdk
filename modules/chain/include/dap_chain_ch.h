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

#define DAP_CHAIN_NODE_SYNC_TIMEOUT 60  // sec
#define DAP_SYNC_TICKS_PER_SECOND   10

typedef struct dap_chain_ch dap_chain_ch_t;
typedef void (*dap_chain_ch_callback_packet_t)(dap_chain_ch_t*, uint8_t a_pkt_type,
                                                      dap_chain_ch_pkt_t *a_pkt, size_t a_pkt_data_size,
                                                      void * a_arg);
typedef struct dap_chain_atom_item{
    dap_chain_hash_fast_t atom_hash;
    dap_chain_atom_ptr_t atom;
    size_t atom_size;
    UT_hash_handle hh;
} dap_chain_atom_item_t;

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

    dap_chain_ch_state_t state;
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

    int timer_shots;
    dap_timerfd_t *activity_timer;
    int sent_breaks;

    dap_chain_ch_callback_packet_t callback_notify_packet_out;
    dap_chain_ch_callback_packet_t callback_notify_packet_in;
    void *callback_notify_arg;
} dap_chain_ch_t;

#define DAP_STREAM_CH_CHAIN(a) ((dap_chain_ch_t *) ((a)->internal) )
#define DAP_STREAM_CH(a) ((dap_stream_ch_t *)((a)->_inheritor))
#define DAP_CHAIN_PKT_EXPECT_SIZE 7168
#define DAP_STREAM_CH_CHAIN_ID 'C'

int dap_chain_ch_init(void);
void dap_chain_ch_deinit(void);

void dap_chain_ch_timer_start(dap_chain_ch_t *a_ch_chain);
void dap_chain_ch_reset_unsafe(dap_chain_ch_t *a_ch_chain);