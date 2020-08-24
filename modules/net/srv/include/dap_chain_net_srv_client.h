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


typedef struct dap_chain_net_srv_client
{
    dap_stream_ch_t * ch; // Use ONLY in own context, not thread-safe
    time_t ts_created;
    dap_stream_worker_t * stream_worker;
    int session_id;
    dap_chain_net_remote_t *net_remote; // For remotes
    uint64_t bytes_received;
    uint64_t bytes_sent;
    struct dap_chain_net_srv_client *prev;
    struct dap_chain_net_srv_client *next;
} dap_chain_net_srv_client_t;
