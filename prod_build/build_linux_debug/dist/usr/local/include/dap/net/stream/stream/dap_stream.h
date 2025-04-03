/*
 Copyright (c) 2017-2018 (c) Project "DeM Labs Inc" https://github.com/demlabsinc
  All rights reserved.

 This file is part of DAP (Distributed Applications Platform) the open source project

    DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
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
#include "dap_http_server.h"
#include "dap_events_socket.h"
#include "dap_config.h"
#include "dap_stream_session.h"
#include "dap_timerfd.h"
#include "dap_sign.h"
#include "dap_cert.h"
#include "dap_pkey.h"
#include "dap_strfuncs.h"
#include "dap_enc_ks.h"

#define STREAM_KEEPALIVE_TIMEOUT    3   // How  often send keeplive messages (seconds)

typedef struct dap_stream_ch dap_stream_ch_t;
typedef struct dap_stream_worker dap_stream_worker_t;
typedef struct dap_cluster dap_cluster_t;

typedef struct dap_stream {
    dap_stream_node_addr_t node;
    bool authorized;
    bool primary;
    int id;
    dap_stream_session_t *session;
    dap_events_socket_t *esocket; // Connection
    dap_events_socket_uuid_t esocket_uuid;
    dap_stream_worker_t *stream_worker;
    struct dap_http_client *conn_http; // HTTP-specific

    dap_timerfd_t *keepalive_timer;
    bool is_active;

    char *service_key;
    bool is_client_to_uplink;

    uint8_t *buf_fragments, *pkt_cache;
    size_t buf_fragments_size_total;// Full size of all fragments
    size_t buf_fragments_size_filled;// Received size

    dap_stream_ch_t **channel;
    size_t channel_count;

    size_t seq_id;
    size_t stream_size;
    size_t client_last_seq_id_packet;

    UT_hash_handle hh;
    struct dap_stream *prev, *next;
} dap_stream_t;

typedef struct dap_stream_info {
    dap_stream_node_addr_t node_addr;
    char *remote_addr_str;
    uint16_t remote_port;
    char *channels;
    size_t total_packets_sent;
    bool is_uplink;
} dap_stream_info_t;

DAP_STATIC_INLINE bool dap_stream_node_addr_str_check(const char *a_addr_str)
{
    if (!a_addr_str)
        return false;
    size_t l_str_len = strlen(a_addr_str);
    if (l_str_len == 22) {
        for (int n =0; n < 22; n+= 6) {
            if (!dap_is_xdigit(a_addr_str[n]) || !dap_is_xdigit(a_addr_str[n + 1]) ||
                !dap_is_xdigit(a_addr_str[n + 2]) || !dap_is_xdigit(a_addr_str[n + 3])) {
                return false;
            }
        }
        for (int n = 4; n < 18; n += 6) {
            if (a_addr_str[n] != ':' || a_addr_str[n + 1] != ':')
                return false;
        }
        return true;
    }
    return false;
}


DAP_STATIC_INLINE char* dap_stream_node_addr_to_str(dap_stream_node_addr_t a_addr, bool a_hex)
{
    if (a_hex)
        return dap_strdup_printf("0x%016" DAP_UINT64_FORMAT_x, a_addr.uint64);
    return dap_strdup_printf(NODE_ADDR_FP_STR, NODE_ADDR_FP_ARGS_S(a_addr));
}


DAP_STATIC_INLINE void dap_stream_node_addr_from_hash(dap_hash_fast_t *a_hash, dap_stream_node_addr_t *a_node_addr)
{
    // Copy fist four and last four octets of hash to fill node addr
    a_node_addr->words[3] = *(uint16_t *)a_hash->raw;
    a_node_addr->words[2] = *(uint16_t *)(a_hash->raw + sizeof(uint16_t));
    a_node_addr->words[1] = *(uint16_t *)(a_hash->raw + DAP_CHAIN_HASH_FAST_SIZE - sizeof(uint16_t) * 2);
    a_node_addr->words[0] = *(uint16_t *)(a_hash->raw + DAP_CHAIN_HASH_FAST_SIZE - sizeof(uint16_t));
}

#define DAP_STREAM(a) ((dap_stream_t *) (a)->_inheritor )

extern dap_stream_node_addr_t g_node_addr;

int dap_stream_init(dap_config_t * g_config);

bool dap_stream_get_dump_packet_headers();

void dap_stream_deinit();

void dap_stream_add_proc_http(dap_http_server_t * sh, const char * url);

void dap_stream_add_proc_udp(dap_server_t *a_udp_server);

dap_stream_t* dap_stream_new_es_client(dap_events_socket_t * a_es, dap_stream_node_addr_t *a_addr, bool a_authorized);
size_t dap_stream_data_proc_read(dap_stream_t * a_stream);
size_t dap_stream_data_proc_write(dap_stream_t * a_stream);
void dap_stream_delete_unsafe(dap_stream_t * a_stream);
void dap_stream_proc_pkt_in(dap_stream_t * sid);

dap_enc_key_type_t dap_stream_get_preferred_encryption_type();
dap_stream_t *dap_stream_get_from_es(dap_events_socket_t *a_es);

// autorization stream block
int dap_stream_add_addr(dap_stream_node_addr_t a_addr, void *a_id);
int dap_stream_add_to_list(dap_stream_t *a_stream);
int dap_stream_delete_addr(dap_stream_node_addr_t a_addr, bool a_full);
int dap_stream_delete_prep_addr(uint64_t a_num_id, void *a_pointer_id);
int dap_stream_add_stream_info(dap_stream_t *a_stream, uint64_t a_id);

dap_events_socket_uuid_t dap_stream_find_by_addr(dap_stream_node_addr_t *a_addr, dap_worker_t **a_worker);
dap_list_t *dap_stream_find_all_by_addr(dap_stream_node_addr_t *a_addr);
dap_stream_node_addr_t dap_stream_node_addr_from_sign(dap_sign_t *a_sign);
dap_stream_node_addr_t dap_stream_node_addr_from_cert(dap_cert_t *a_cert);
dap_stream_node_addr_t dap_stream_node_addr_from_pkey(dap_pkey_t *a_pkey);
dap_stream_info_t *dap_stream_get_links_info(dap_cluster_t *a_cluster, size_t *a_count);
void dap_stream_delete_links_info(dap_stream_info_t *a_info, size_t a_count);
