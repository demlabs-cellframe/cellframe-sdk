/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2019
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
*/
#pragma once

#include <stdint.h>
#include "dap_enc_key.h"
#include "dap_events.h"
/**
 * @brief The dap_client_stage enum. Top level of client's state machine
 **/
typedef enum dap_client_stage {
    STAGE_BEGIN=0,
    STAGE_ENC_INIT=1,
    STAGE_STREAM_CTL=2,
    STAGE_STREAM=3,
} dap_client_stage_t;

typedef enum dap_client_stage_status {
    STAGE_STATUS_NONE=0,
    // Enc init stage
    STAGE_STATUS_IN_PROGRESS,
    STAGE_STATUS_ABORTING,
    STAGE_STATUS_ERROR,
    STAGE_STATUS_DONE,
} dap_client_stage_status_t;

typedef enum dap_client_error {
    ERROR_NO_ERROR = 0,
    ERROR_ENC_NO_KEY,
    ERROR_ENC_WRONG_KEY,
    ERROR_STREAM_CTL_ERROR,
    ERROR_STREAM_CTL_ERROR_AUTH,
    ERROR_STREAM_CTL_ERROR_RESPONSE_FORMAT,
    ERROR_STREAM_RESPONSE_WRONG,
    ERROR_STREAM_RESPONSE_TIMEOUT,
    ERROR_STREAM_FREEZED,
    ERROR_NETWORK_CONNECTION_REFUSE
} dap_client_error_t;

#define DAP_CLIENT_PROTOCOL_VERSION 22

/**
 * @brief The dap_client struct
 */
typedef struct dap_client{
    void * _internal;
    void * _inheritor;
} dap_client_t;

typedef void (*dap_client_callback_t) (dap_client_t *, void*);
typedef void (*dap_client_callback_int_t) (dap_client_t *, int);
typedef void (*dap_client_callback_data_size_t) (dap_client_t *, void *, size_t);

#define DAP_UPLINK_PATH_ENC_INIT         "1901248124123459"
#define DAP_UPLINK_PATH_DB               "01094787531354"
#define DAP_UPLINK_PATH_STREAM_CTL       "091348758013553"
#define DAP_UPLINK_PATH_STREAM           "874751843144"
#define DAP_UPLINK_PATH_LICENSE          "license"
#define DAP_UPLINK_PATH_SERVER_LIST      "slist"

#ifdef __cplusplus
extern "C" {
#endif

int dap_client_init();
void dap_client_deinit();

dap_client_t * dap_client_new(dap_events_t * a_events, dap_client_callback_t a_stage_status_callback
                              , dap_client_callback_t a_stage_status_error_callback );
void dap_client_delete(dap_client_t * a_client);


dap_enc_key_t * dap_client_get_key_stream(dap_client_t * a_client);

void dap_client_go_stage(dap_client_t * a_client, dap_client_stage_t a_stage_end, dap_client_callback_t a_stage_end_callback);

void dap_client_reset(dap_client_t * a_client);

void dap_client_request_enc(dap_client_t * a_client, const char * a_path,const char * a_suburl,const char* a_query, void * a_request, size_t a_request_size,
                                dap_client_callback_data_size_t a_response_proc, dap_client_callback_int_t a_response_error);


const char * dap_client_get_stage_str(dap_client_t * a_client);
const char * dap_client_stage_str(dap_client_stage_t a_stage);

const char * dap_client_get_stage_status_str(dap_client_t * a_client);
const char * dap_client_stage_status_str(dap_client_stage_status_t a_stage_status);
const char * dap_client_error_str(dap_client_error_t a_client_error);
const char * dap_client_get_error_str(dap_client_t * a_client);

const char * dap_client_get_auth_cookie(dap_client_t * a_client);
const char * dap_client_get_stream_id(dap_client_t * a_client);

dap_client_stage_t dap_client_get_stage(dap_client_t * a_client);
dap_client_stage_status_t dap_client_get_stage_status(dap_client_t * a_client);

#ifdef __cplusplus
}
#endif
