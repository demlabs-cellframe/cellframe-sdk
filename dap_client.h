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
*/
#pragma once

typedef enum dap_client_stage{ DAP_CLIENT_DISCONNECTED=0,DAP_CLIENT_CONNECTING=1,
                              DAP_CLIENT_CONNECTED_HTTP_HEADERS=2,
                      DAP_CLIENT_CONNECTED_STREAMING=3 } dap_client_stage_t;
typedef struct dap_client {
    void * _internal;
    dap_client_stage_t stage;
} dap_client_t;

typedef void (*dap_client_callback_t) (dap_client_t *, void*);
typedef dap_stream_t;
typedef dap_events_t;

#define DAP_CLIENT(a) ((dap_client_t *) (a)->_inheritor )

dap_client_t * dap_client_new(dap_events_t * a_events,const char * a_name);

void dap_client_set_callback_error(dap_client_t * a_client, dap_client_callback_t a_client_callback_error);
void dap_client_set_callback_connected(dap_client_t * a_client, dap_client_callback_t a_client_callback_connected);
void dap_client_set_callback_disconnected(dap_client_t * a_client, dap_client_callback_t a_client_callback_disconnected);
int dap_client_delete(dap_client_t * a_client);
