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

#include "pthread.h"
#include "uthash.h"
#include "dap_stream_session.h"
#include "dap_hash.h"
#include "dap_chain.h"
#include "dap_sign.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_receipt.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_wallet.h"

typedef struct dap_chain_net_srv dap_chain_net_srv_t;
typedef struct dap_chain_net_srv_client_remote dap_chain_net_srv_client_remote_t;

typedef struct dap_chain_net_srv_usage{
    uint32_t id; // Usage id
    pthread_rwlock_t rwlock;
    time_t ts_created; // Created timpestamp
    dap_chain_net_t * net; // Chain network where everything happens
    dap_chain_net_srv_t * service; // Service that used

    dap_chain_datum_tx_receipt_t* receipt;
    dap_chain_datum_tx_receipt_t* receipt_next; // Receipt on the next units amount
    dap_chain_net_srv_price_t * price; // Price for issue next receipt
    dap_chain_net_srv_client_remote_t *client;
    dap_chain_datum_tx_t * tx_cond;
    dap_chain_hash_fast_t tx_cond_hash;
    dap_chain_hash_fast_t client_pkey_hash;
    char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    bool is_active;
    bool is_free;
    bool is_grace;
    UT_hash_handle hh; //
} dap_chain_net_srv_usage_t;

typedef struct dap_net_stats{
        uintmax_t bytes_sent;
        uintmax_t bytes_recv;
        uintmax_t bytes_sent_lost;
        uintmax_t bytes_recv_lost;

        uintmax_t packets_sent;
        uintmax_t packets_recv;
        uintmax_t packets_sent_lost;
        intmax_t packets_recv_lost;
} dap_net_stats_t;

typedef struct dap_chain_net_srv_stream_session {
    time_t ts_activated;
    dap_stream_session_t * parent;
    dap_chain_net_srv_usage_t * usages;
    dap_chain_net_srv_usage_t * usage_active;
    uintmax_t limits_bytes; // Bytes left
    time_t limits_ts; // Timestamp until its activte
    dap_chain_net_srv_price_unit_uid_t limits_units_type;

    // Some common stats
    volatile dap_net_stats_t stats;

    dap_sign_t* user_sign; // User's signature for auth if reconnect

} dap_chain_net_srv_stream_session_t;

#define DAP_CHAIN_NET_SRV_STREAM_SESSION(a) ((dap_chain_net_srv_stream_session_t *) (a)->_inheritor )

dap_chain_net_srv_stream_session_t * dap_chain_net_srv_stream_session_create( dap_stream_session_t * a_session);
dap_chain_net_srv_usage_t* dap_chain_net_srv_usage_add (dap_chain_net_srv_stream_session_t * a_srv_session,
                                                                            dap_chain_net_t * a_net, dap_chain_net_srv_t * a_srv);
void dap_chain_net_srv_usage_delete (dap_chain_net_srv_stream_session_t * a_srv_session,
                                                                               dap_chain_net_srv_usage_t* a_usage);
dap_chain_net_srv_usage_t* dap_chain_net_srv_usage_find_unsafe (dap_chain_net_srv_stream_session_t * a_srv_session,
                                                                             uint32_t a_usage_id);
