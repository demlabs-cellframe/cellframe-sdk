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
#include "dap_chain_wallet.h"


#define RECEIPT_SIGN_MAX_ATTEMPT 3
typedef struct dap_chain_net_srv dap_chain_net_srv_t;
typedef struct dap_chain_net_srv_client_remote dap_chain_net_srv_client_remote_t;
typedef struct dap_chain_net_srv_price dap_chain_net_srv_price_t;

typedef enum dap_chain_net_srv_usage_service_state{
    DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_IDLE = 0, //Initial state.
    DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_GRACE, // Start of service when tx for paying is not in the leger yet.
    DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_NORMAL, // Normal state after first receipt paid.
    DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_ERROR, // Error state, stop of service providing.
    DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_FREE, // The only state in free mode.
} dap_chain_net_srv_usage_service_state_t;

typedef enum dap_chain_net_srv_usage_service_substate{
    DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_IDLE=0, // Initial substate.
    DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_FIRST_RECEIPT_SIGN, // Waiting responce from client with first receipt sign.
    DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_NEXT_RECEIPT_SIGN, // Waiting responce from client with next receipt sign in normal state.
    DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_TX_FOR_PAYING, // Waiting previous transaction validation to pay next receipt.
    DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_NEW_TX_FROM_CLIENT, // Waiting new tx from client for receipt paying, because previous tx has not enough funds.
    DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_RECEIPT_FOR_NEW_TX_FROM_CLIENT, // Waiting new receipt with new tx from client.
    DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_NEW_TX_IN_LEDGER, // Waiting new tx validation.
    DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_NORMAL, // Substate for normal work. Current service is paid, nothing waiting.
    DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_ERROR, // Error sustate. Wait current service is over and go to error state.
} dap_chain_net_srv_usage_service_substate_t;


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
    dap_chain_hash_fast_t static_order_hash;
    dap_timerfd_t *save_limits_timer;
    dap_timerfd_t *receipts_timeout_timer;
    void (*receipt_timeout_timer_start_callback)(struct dap_chain_net_srv_usage *a_usage);
    int receipt_sign_req_cnt;
    char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];

    bool is_active;
    bool is_limits_changed;

    dap_chain_net_srv_usage_service_state_t service_state;
    dap_chain_net_srv_usage_service_substate_t service_substate;
    uint32_t last_err_code;
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
    dap_chain_net_srv_usage_t * usage_active;
    intmax_t limits_bytes; // Bytes provided for using the service left
    time_t limits_ts; //Time provided for using the service

    time_t last_update_ts; //Time provided for using the service

    dap_chain_net_srv_price_unit_uid_t limits_units_type;

    // Some common stats
    volatile dap_net_stats_t stats;

    dap_sign_t* user_sign; // User's signature for auth if reconnect

} dap_chain_net_srv_stream_session_t;

#define DAP_CHAIN_NET_SRV_STREAM_SESSION(a) ((dap_chain_net_srv_stream_session_t *) (a)->_inheritor )

dap_chain_net_srv_stream_session_t * dap_chain_net_srv_stream_session_create( dap_stream_session_t * a_session);
void dap_chain_net_srv_stream_session_delete( dap_stream_session_t * a_session);
dap_chain_net_srv_usage_t* dap_chain_net_srv_usage_add (dap_chain_net_srv_stream_session_t * a_srv_session,
                                                                            dap_chain_net_t * a_net, dap_chain_net_srv_t * a_srv);
void dap_chain_net_srv_usage_delete (dap_chain_net_srv_stream_session_t * a_srv_session);
dap_chain_net_srv_usage_t* dap_chain_net_srv_usage_find_unsafe (dap_chain_net_srv_stream_session_t * a_srv_session,
                                                                             uint32_t a_usage_id);
