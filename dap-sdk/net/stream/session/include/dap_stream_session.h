/*
 Copyright (c) 2017-2018 (c) Project "DeM Labs Inc" https://gitlab.com/demlabsinc
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

#include <pthread.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>

#ifndef _WIN32
#include <netinet/in.h>
#endif

#include "uthash.h"
#include "dap_enc_key.h"
#include "dap_hash.h"
#include "dap_list.h"

typedef enum stream_session_type {STREAM_SESSION_TYPE_MEDIA=0,STREAM_SESSION_TYPE_VPN} stream_session_type_t;
typedef enum stream_session_connection_type {STEAM_SESSION_HTTP = 0, STREAM_SESSION_UDP, STREAM_SESSION_END_TYPE} stream_session_connection_type_t;

typedef struct dap_stream_session dap_stream_session_t;
typedef void (*dap_stream_session_callback_t)( dap_stream_session_t *,void*);

struct dap_stream_session {
    bool create_empty;
    unsigned int id;
    unsigned int media_id;

    dap_enc_key_t * key;

    bool open_preview;
    pthread_mutex_t mutex;
    int opened;
    time_t time_created;

    uint8_t enc_type;
    int32_t protocol_version;

    char *service_key;// auth string
    char active_channels[16];// channels for open

    stream_session_connection_type_t conn_type;
    stream_session_type_t type;
    uint8_t *acl;
    UT_hash_handle hh;
    struct in_addr tun_client_addr;

    void * _inheritor;

    dap_stream_session_callback_t callback_delete;
};
typedef struct dap_stream_session dap_stream_session_t;

void dap_stream_session_init();
void dap_stream_session_deinit();
dap_list_t* dap_stream_session_get_list_sessions(void);
void dap_stream_session_get_list_sessions_unlock(void);

dap_stream_session_t * dap_stream_session_pure_new();
dap_stream_session_t * dap_stream_session_new(unsigned int media_id, bool open_preview);
dap_stream_session_t * dap_stream_session_id_mt(unsigned int id);
dap_stream_session_t *dap_stream_session_id_unsafe( unsigned int id );
void dap_stream_session_lock();
void dap_stream_session_unlock();

int dap_stream_session_open(dap_stream_session_t * a_session); /*Lock for opening for single client , return 0 if ok*/
int dap_stream_session_close_mt(unsigned int id);

