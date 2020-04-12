/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
 * All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
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
#include "dap_chain_global_db_hist.h"
#include "dap_list.h"
#include "dap_stream_ch_chain_pkt.h"
#include "uthash.h"


typedef struct dap_stream_ch_chain dap_stream_ch_chain_t;
typedef void (*dap_stream_ch_chain_callback_packet_t)(dap_stream_ch_chain_t*, uint8_t a_pkt_type,
                                                      dap_stream_ch_chain_pkt_t *a_pkt, size_t a_pkt_data_size,
                                                      void * a_arg);
typedef struct dap_chain_atom_item{
    dap_chain_hash_fast_t atom_hash;
    dap_chain_atom_ptr_t atom;
    UT_hash_handle hh;
} dap_chain_atom_item_t;

typedef struct dap_stream_ch_chain {
    pthread_mutex_t mutex;
    dap_stream_ch_t * ch;

    dap_db_log_list_t *request_global_db_trs; // list of transactions
    dap_stream_ch_chain_state_t state;

    dap_chain_atom_iter_t * request_atom_iter;
    dap_chain_atom_item_t * request_atoms_lasts;
    dap_chain_atom_item_t * request_atoms_processed;
    uint64_t stats_request_atoms_processed;
    uint64_t stats_request_gdb_processed;
    dap_stream_ch_chain_sync_request_t request;
    dap_chain_net_id_t request_net_id;
    dap_chain_id_t request_chain_id;
    dap_chain_cell_id_t request_cell_id;
    time_t request_last_ts;

    dap_stream_ch_chain_callback_packet_t callback_notify_packet_out;
    dap_stream_ch_chain_callback_packet_t callback_notify_packet_in;
    void *callback_notify_arg;
} dap_stream_ch_chain_t;

#define DAP_STREAM_CH_CHAIN(a) ((dap_stream_ch_chain_t *) ((a)->internal) )


int dap_stream_ch_chain_init(void);
void dap_stream_ch_chain_deinit(void);

inline static uint8_t dap_stream_ch_chain_get_id(void) { return (uint8_t) 'C'; }
void dap_stream_ch_chain_go_idle ( dap_stream_ch_chain_t * a_ch_chain);
