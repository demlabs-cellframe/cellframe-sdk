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

#include "uthash.h"
#include "dap_stream_session.h"
#include "dap_hash.h"
#include "dap_chain.h"
#include "dap_sign.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_receipt.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_net_srv_order.h"

typedef struct dap_stream_ch_chain_net_srv_usage{
    uint32_t id; // Usage id
    dap_chain_net_t * net; // Chain network where everything happens
    dap_chain_net_srv_t * service; // Service that used
    dap_chain_datum_tx_receipt_t* receipt_active;
    UT_hash_handle hh; //
} dap_stream_ch_chain_net_srv_usage_t;

typedef struct dap_stream_ch_chain_net_srv_session {
    dap_stream_session_t * parent;
    dap_stream_ch_chain_net_srv_usage_t * usages;
    dap_sign_t* user_sign; // User's signature for auth if reconnect
} dap_stream_ch_chain_net_srv_session_t;

dap_stream_ch_chain_net_srv_session_t * dap_stream_ch_chain_net_srv_session_create( dap_stream_session_t * a_session);
dap_stream_ch_chain_net_srv_usage_t* dap_stream_ch_chain_net_srv_usage_add (dap_stream_ch_chain_net_srv_session_t * a_srv_session,
                                                                            dap_chain_net_t * a_net, dap_chain_net_srv_t * a_srv);
void dap_stream_ch_chain_net_srv_usage_delete (dap_stream_ch_chain_net_srv_session_t * a_srv_session,
                                                                               dap_stream_ch_chain_net_srv_usage_t* a_usage);
dap_stream_ch_chain_net_srv_usage_t* dap_stream_ch_chain_net_srv_usage_find (dap_stream_ch_chain_net_srv_session_t * a_srv_session,
                                                                             uint32_t a_usage_id);
