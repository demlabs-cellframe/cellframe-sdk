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
#include <pthread.h>

#include "dap_config.h"
#include "dap_stream_session.h"
#include "dap_stream_ch.h"

#include "dap_events_socket.h"

#define CHUNK_SIZE_MAX (3 * 1024)

typedef struct dap_client_remote dap_client_remote_t;
typedef struct dap_udp_server dap_udp_server_t;


typedef struct dap_http_client dap_http_client_t;
typedef struct dap_http dap_http_t;
typedef struct dap_stream dap_stream_t;
typedef struct dap_stream_pkt dap_stream_pkt_t;
typedef struct dap_events_socket dap_events_socket_t;
#define STREAM_BUF_SIZE_MAX 500000
#define STREAM_KEEPALIVE_TIMEOUT 3   // How  often send keeplive messages (seconds)

typedef void (*dap_stream_callback)( dap_stream_t *,void*);

typedef struct dap_stream {
    int id;
    dap_stream_session_t * session;
    dap_events_socket_t * esocket; // Connection
    uint128_t esocket_uuid;
    dap_stream_worker_t * stream_worker;
    struct dap_http_client * conn_http; // HTTP-specific

    char * service_key;

    bool is_live;
    bool is_client_to_uplink ;

    struct dap_stream_pkt * in_pkt;
    struct dap_stream_pkt *pkt_buf_in;
    size_t pkt_buf_in_data_size;
    size_t pkt_buf_in_size_expected;

    uint8_t buf_defrag[STREAM_BUF_SIZE_MAX];
    uint64_t buf_defrag_size;

    uint8_t buf[STREAM_BUF_SIZE_MAX];
    uint8_t pkt_cache[STREAM_BUF_SIZE_MAX];

    dap_stream_ch_t *channel[255]; // TODO reduce channels to 16 to economy memory
    size_t channel_count;

    size_t frame_sent; // Frame counter

    size_t seq_id;
    size_t stream_size;
    size_t client_last_seq_id_packet;

    struct dap_stream *prev, *next;

} dap_stream_t;

#define DAP_STREAM(a) ((dap_stream_t *) (a)->_inheritor )

int dap_stream_init(dap_config_t * g_config);

bool dap_stream_get_dump_packet_headers();

void dap_stream_deinit();

void dap_stream_add_proc_http(dap_http_t * sh, const char * url);

void dap_stream_add_proc_udp(dap_server_t *a_udp_server);

dap_stream_t* dap_stream_new_es_client(dap_events_socket_t * a_es);
size_t dap_stream_data_proc_read(dap_stream_t * a_stream);
size_t dap_stream_data_proc_write(dap_stream_t * a_stream);
void dap_stream_delete(dap_stream_t * a_stream);
void dap_stream_proc_pkt_in(dap_stream_t * sid);

void dap_stream_es_rw_states_update(struct dap_stream *a_stream);
void dap_stream_set_ready_to_write(dap_stream_t * a_stream,bool a_is_ready);

dap_enc_key_type_t dap_stream_get_preferred_encryption_type();


