/*
* Authors:
* Dmitriy Gerasimov <naeper@demlabs.net>
* Cellframe       https://cellframe.net
* DeM Labs Inc.   https://demlabs.net
* Copyright  (c) 2017-2019
* All rights reserved.

This file is part of CellFrame SDK the open source project

CellFrame SDK is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

CellFrame SDK is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once

#include <stdint.h>
#include <time.h>


#include "dap_enc_key.h"
#include "dap_stream_session.h"
#include "dap_stream_worker.h"
#include "dap_chain_net_srv_common.h"
#include "dap_chain_net_remote.h"
#include "dap_chain_node_client.h"

typedef struct dap_chain_net_srv_client dap_chain_net_srv_client_t;

typedef void (*dap_chain_net_srv_client_callback_t)(dap_chain_net_srv_client_t *, void *);

typedef struct dap_chain_net_srv_client_callbacks {
    dap_chain_net_srv_client_callback_t connected;
    dap_chain_net_srv_client_callback_t disconnected;
    dap_chain_net_srv_client_callback_t deleted;
    dap_stream_ch_callback_packet_t pkt_in;
} dap_chain_net_srv_client_callbacks_t;

typedef struct dap_chain_net_srv_client {
    dap_chain_net_srv_client_callbacks_t callbacks;
    void *callbacks_arg;
    dap_stream_ch_uuid_t ch_uuid;
    dap_chain_node_client_t *node_client;
    dap_client_t *net_client;
    void *_inheritor;
} dap_chain_net_srv_client_t;

dap_chain_net_srv_client_t *dap_chain_net_srv_client_create_n_connect(dap_chain_net_t *a_net, char *a_addr, uint16_t a_port,
                                                                      dap_chain_net_srv_client_callbacks_t *a_callbacks,
                                                                      void *a_callbacks_arg);
ssize_t dap_chain_net_srv_client_write(dap_chain_net_srv_client_t *a_client, uint8_t a_type, void *a_pkt_data, size_t a_pkt_data_size);
