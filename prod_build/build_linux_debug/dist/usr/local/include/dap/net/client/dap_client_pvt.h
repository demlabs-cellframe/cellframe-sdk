/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Ltd.   https://demlabs.net
 * Copyright  (c) 2017-2020
 * All rights reserved.

 This file is part of DAP SDK the open source project

    DAP SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "dap_client.h"
#include "dap_client_http.h"
#include "dap_stream.h"
#include "dap_events_socket.h"
#include "dap_cert.h"

typedef struct dap_enc_key dap_enc_key_t;
typedef struct dap_http_client dap_http_client_t;

typedef struct dap_client_pvt {
    dap_client_t *client;

    dap_stream_t *stream;
    dap_stream_worker_t *stream_worker;
    dap_events_socket_t *stream_es;
    bool authorized;

    dap_worker_t *worker;
    dap_client_http_t *http_client;

    dap_enc_key_type_t session_key_type;
    dap_enc_key_type_t session_key_open_type;
    size_t session_key_block_size;

    dap_enc_key_t *session_key_open; // Open assymetric keys exchange
    dap_enc_key_t *session_key; // Symmetric private key for session encryption
    dap_enc_key_t *stream_key; // Stream private key for stream encryption
    uint32_t stream_id;
    char *session_key_id;
    uint32_t uplink_protocol_version;
    uint32_t remote_protocol_version;

    dap_client_stage_t stage;
    dap_client_stage_status_t stage_status;
    dap_client_error_t last_error;

    dap_client_callback_t stage_status_done_callback;

    int reconnect_attempts;

    bool is_encrypted;
    bool is_encrypted_headers;
    bool is_close_session;// the last request in session, in the header will be added "SessionCloseAfterRequest: true"
    bool is_closed_by_timeout;
    time_t ts_last_active;

    bool is_removing;

    dap_client_callback_data_size_t request_response_callback;
    dap_client_callback_int_t request_error_callback;
    void *callback_arg;

    dap_list_t *pkt_queue;
    dap_timerfd_t *reconnect_timer;
} dap_client_pvt_t;

typedef struct dap_client_pkt_queue_elm {
    char ch_id;
    uint8_t type;
    size_t data_size;
    byte_t data[];
} dap_client_pkt_queue_elm_t;

#define DAP_CLIENT_PVT(a) ((a) ? (dap_client_pvt_t *)(a)->_internal : NULL)

int dap_client_pvt_init();
void dap_client_pvt_deinit();

void dap_client_pvt_stage_transaction_begin(dap_client_pvt_t * dap_client_pvt_t, dap_client_stage_t a_stage_next,
                                                 dap_client_callback_t a_done_callback);

int dap_client_pvt_request(dap_client_pvt_t * a_client_internal, const char * a_path, void * a_request,
                    size_t a_request_size,  dap_client_callback_data_size_t a_response_proc, dap_client_callback_int_t a_response_error);

void dap_client_pvt_request_enc(dap_client_pvt_t * a_client_internal, const char * a_path, const char * a_sub_url,
                                     const char * a_query, void * a_request, size_t a_request_size,
                                dap_client_callback_data_size_t a_response_proc,
                                     dap_client_callback_int_t a_error_proc);

void dap_client_pvt_new(dap_client_pvt_t *a_client_internal);
void dap_client_pvt_delete_unsafe(dap_client_pvt_t *a_client_pvt);
void dap_client_pvt_queue_add(dap_client_pvt_t *a_client_pvt, const char a_ch_id, uint8_t a_type, void *a_data, size_t a_data_size);
int dap_client_pvt_queue_clear(dap_client_pvt_t *a_client_pvt);
