/*
 Copyright (c) 2017-2018 (c) Project "DeM Labs Inc" https://github.com/demlabsinc
  All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <pthread.h>
#include <stdbool.h>
#include <ev.h>

#include "dap_stream_session.h"
#include "dap_stream_ch.h"
//#include "dap_udp_server.h"
//#include "dap_udp_client.h"
#include "dap_events_socket.h"
#include "dap_udp_server.h"
#include "dap_udp_client.h"

#define CHUNK_SIZE_MAX 3*1024

typedef struct dap_client_remote dap_client_remote_t;
typedef struct dap_udp_server dap_udp_server_t;


typedef struct dap_http_client dap_http_client_t;
typedef struct dap_http dap_http_t;
typedef struct dap_stream dap_stream_t;
typedef struct dap_stream_pkt dap_stream_pkt_t;
typedef struct dap_events_socket dap_events_socket_t;
#define STREAM_BUF_SIZE_MAX 500000
#define STREAM_KEEPALIVE_TIMEOUT 3   // How  often send keeplive messages (seconds)
#define STREAM_KEEPALIVE_PASSES 3    // How many messagges without answers need for disconnect client and close session

typedef void (*dap_stream_callback)( dap_stream_t *,void*);

typedef struct dap_stream {

    int id;
    dap_stream_session_t * session;
    struct dap_client_remote * conn; // Connection

    struct dap_http_client * conn_http; // HTTP-specific

    struct dap_udp_client * conn_udp; // UDP-client
    dap_events_socket_t * events_socket;

    bool is_live;
    bool is_client_to_uplink ;

    ev_timer keepalive_watcher;         // Watcher for keepalive loop
    uint8_t keepalive_passed;           // Number of sended keepalive messages

    struct dap_stream_pkt * in_pkt;
    struct dap_stream_pkt *pkt_buf_in;
    size_t pkt_buf_in_data_size;
    size_t pkt_buf_in_size_expected;

    uint8_t buf_defrag[STREAM_BUF_SIZE_MAX];
    uint64_t buf_defrag_size;

    uint8_t buf[STREAM_BUF_SIZE_MAX];
    uint8_t buf_pkt_in[STREAM_BUF_SIZE_MAX];

    dap_stream_ch_t * channel[255]; // TODO reduce channels to 16 to economy memory
    size_t channel_count;

    char *service_key;

    size_t frame_sent; // Frame counter

    size_t seq_id;
    size_t stream_size;
    size_t client_last_seq_id_packet;

} dap_stream_t;

#define DAP_STREAM(a) ((dap_stream_t *) (a)->_internal )

int dap_stream_init();

void dap_stream_deinit();

void dap_stream_add_proc_http(dap_http_t * sh, const char * url);

void dap_stream_add_proc_udp(dap_udp_server_t * sh);

dap_stream_t* dap_stream_new_es(dap_events_socket_t * a_es);
size_t dap_stream_data_proc_read(dap_stream_t * a_stream);
size_t dap_stream_data_proc_write(dap_stream_t * a_stream);
void dap_stream_delete(dap_stream_t * a_stream);
void dap_stream_proc_pkt_in(dap_stream_t * sid);

void dap_stream_es_rw_states_update(struct dap_stream *a_stream);


