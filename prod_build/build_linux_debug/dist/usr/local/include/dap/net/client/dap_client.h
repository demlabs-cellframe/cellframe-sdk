/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Cellframe Network https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2019
 * All rights reserved.

 This file is part of DAP (Distributed Applications Platform) the open source project

    DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once

#include "dap_events.h"
#include <stdint.h>
#include "dap_enc_key.h"
#include "dap_stream.h"
#include "dap_stream_ch.h"
#include "dap_cert.h"

/**
 * @brief The dap_client_stage enum. Top level of client's state machine
 **/
typedef enum dap_client_stage {
    STAGE_UNDEFINED=-1,
    STAGE_BEGIN=0,
    STAGE_ENC_INIT=1,
    STAGE_STREAM_CTL=2,
    STAGE_STREAM_SESSION=3,
    STAGE_STREAM_CONNECTED=4,
    STAGE_STREAM_STREAMING=5
} dap_client_stage_t;

typedef enum dap_client_stage_status {
    STAGE_STATUS_NONE=0,
    STAGE_STATUS_IN_PROGRESS,
    STAGE_STATUS_ERROR,
    STAGE_STATUS_DONE,
    STAGE_STATUS_COMPLETE
} dap_client_stage_status_t;

typedef enum dap_client_error {
    ERROR_NO_ERROR = 0,
    ERROR_OUT_OF_MEMORY,
    ERROR_ENC_NO_KEY,
    ERROR_ENC_WRONG_KEY,
    ERROR_ENC_SESSION_CLOSED,
    ERROR_STREAM_CTL_ERROR,
    ERROR_STREAM_CTL_ERROR_AUTH,
    ERROR_STREAM_CTL_ERROR_RESPONSE_FORMAT,
    ERROR_STREAM_CONNECT,
    ERROR_STREAM_RESPONSE_WRONG,
    ERROR_STREAM_RESPONSE_TIMEOUT,
    ERROR_STREAM_FREEZED,
    ERROR_STREAM_ABORTED,
    ERROR_NETWORK_CONNECTION_REFUSE,
    ERROR_NETWORK_CONNECTION_TIMEOUT,
    ERROR_WRONG_STAGE,
    ERROR_WRONG_ADDRESS
} dap_client_error_t;

typedef struct dap_client dap_client_t;

typedef void (*dap_client_callback_t) (dap_client_t *, void *);
typedef void (*dap_client_callback_int_t) (dap_client_t *, void *, int);
typedef void (*dap_client_callback_data_size_t) (dap_client_t *, void *, size_t);

typedef struct dap_link_info {
    dap_stream_node_addr_t node_addr;
    char uplink_addr[DAP_HOSTADDR_STRLEN];
    uint16_t uplink_port;
} DAP_ALIGN_PACKED dap_link_info_t;

/**
 * @brief The dap_client struct
 */
typedef struct dap_client {
    char *active_channels;

    dap_link_info_t link_info;

    dap_cert_t *auth_cert;

    bool always_reconnect; // Always reconnect ever number of tries are over
    bool connect_on_demand; // Automatically connect with writing request

    dap_client_stage_t stage_target;
    dap_client_callback_t stage_target_done_callback;
    dap_client_callback_t stage_status_error_callback;
    void *callbacks_arg;

    void *_internal;
    void *_inheritor;
} dap_client_t;

#define DAP_ESOCKET_CLIENT(a) (a ? (dap_client_t *)a->_inheritor : NULL)

#define DAP_UPLINK_PATH_ENC_INIT         "enc_init"
#define DAP_UPLINK_PATH_STREAM_CTL       "stream_ctl"
#define DAP_UPLINK_PATH_STREAM           "stream"
#define DAP_UPLINK_PATH_LICENSE          "license"
#define DAP_UPLINK_PATH_NODE_LIST        "nodelist_add"
#define DAP_UPLINK_PATH_BALANCER         "balancer"

#ifdef __cplusplus
extern "C" {
#endif

int dap_client_init();
void dap_client_deinit();

dap_client_t *dap_client_new(dap_client_callback_t a_stage_status_error_callback, void *a_callbacks_arg);

DAP_STATIC_INLINE const char* dap_client_get_uplink_addr_unsafe(dap_client_t *a_client) { return a_client->link_info.uplink_addr; }
DAP_STATIC_INLINE uint16_t dap_client_get_uplink_port_unsafe(dap_client_t *a_client) { return a_client->link_info.uplink_port; }

void dap_client_set_uplink_unsafe(dap_client_t *a_client, dap_stream_node_addr_t *a_node, const char *a_addr, uint16_t a_port);
dap_enc_key_t * dap_client_get_key_stream(dap_client_t * a_client);

void dap_client_go_stage(dap_client_t * a_client, dap_client_stage_t a_stage_end, dap_client_callback_t a_stage_end_callback);
void dap_client_delete_mt(dap_client_t * a_client);
void dap_client_delete_unsafe(dap_client_t * a_client);

ssize_t dap_client_write_unsafe(dap_client_t *a_client, const char a_ch_id, uint8_t a_type, void *a_data, size_t a_data_size);
int dap_client_write_mt(dap_client_t *a_client, const char a_ch_id, uint8_t a_type, void *a_data, size_t a_data_size);
void dap_client_queue_clear(dap_client_t *a_client);

void dap_client_request_enc_unsafe(dap_client_t * a_client, const char * a_path,const char * a_suburl,const char* a_query, void * a_request, size_t a_request_size,
                                dap_client_callback_data_size_t a_response_proc, dap_client_callback_int_t a_response_error);

void dap_client_request_unsafe(dap_client_t * a_client, const char * a_full_path, void * a_request, size_t a_request_size,
                                dap_client_callback_data_size_t a_response_proc, dap_client_callback_int_t a_response_error);

//int dap_client_disconnect(dap_client_t * a_client);

const char * dap_client_get_stage_str(dap_client_t * a_client);
const char * dap_client_stage_str(dap_client_stage_t a_stage);

const char * dap_client_get_stage_status_str(dap_client_t * a_client);
const char * dap_client_stage_status_str(dap_client_stage_status_t a_stage_status);
const char * dap_client_error_str(dap_client_error_t a_client_error);
const char * dap_client_get_error_str(dap_client_t * a_client);


bool dap_client_get_is_always_reconnect(dap_client_t * a_client);
void dap_client_set_is_always_reconnect(dap_client_t * a_client, bool a_value);

dap_client_t * dap_client_from_esocket(dap_events_socket_t * a_esocket);
const char * dap_client_get_auth_cookie(dap_client_t * a_client);
dap_stream_t * dap_client_get_stream(dap_client_t * a_client);
dap_stream_worker_t * dap_client_get_stream_worker(dap_client_t * a_client);
dap_stream_ch_t * dap_client_get_stream_ch_unsafe(dap_client_t * a_client, uint8_t a_ch_id);
uint32_t dap_client_get_stream_id(dap_client_t * a_client);
void dap_client_set_active_channels_unsafe (dap_client_t * a_client, const char * a_active_channels);
void dap_client_set_auth_cert(dap_client_t *a_client, const char *a_cert_name);

dap_client_stage_t dap_client_get_stage(dap_client_t * a_client);
dap_client_stage_status_t dap_client_get_stage_status(dap_client_t * a_client);

#ifdef __cplusplus
}
#endif
