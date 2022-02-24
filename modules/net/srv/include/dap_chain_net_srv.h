/*
* Authors:
* Dmitriy Gerasimov <naeper@demlabs.net>
* Aleksandr Lysikov <alexander.lysikov@demlabs.net>
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

#include "dap_config.h"
#include "dap_chain_net_srv_common.h"
#include "dap_chain_net_srv_client.h"
#include "dap_chain_net_srv_stream_session.h"

typedef struct dap_chain_net_srv dap_chain_net_srv_t;

typedef void (*dap_chain_net_srv_callback_t)(dap_chain_net_srv_t *, dap_chain_net_srv_client_remote_t *);
typedef int (*dap_chain_net_srv_callback_data_t)(dap_chain_net_srv_t *, uint32_t, dap_chain_net_srv_client_remote_t *, const void *, size_t );
typedef void* (*dap_chain_net_srv_callback_data_with_out_data_t)(dap_chain_net_srv_t *, uint32_t, dap_chain_net_srv_client_remote_t *, const void *, size_t, size_t *);
typedef int (*dap_chain_net_srv_callback_sign_request_t)(dap_chain_net_srv_t *, uint32_t, dap_chain_net_srv_client_remote_t *, dap_chain_datum_tx_receipt_t **, size_t );
typedef void (*dap_chain_net_srv_callback_ch_t)(dap_chain_net_srv_t *, dap_stream_ch_t *);

typedef struct dap_chain_net_srv_banlist_item {
    dap_chain_hash_fast_t client_pkey_hash;
    pthread_mutex_t *ht_mutex;
    struct dap_chain_net_srv_banlist_item **ht_head;
    UT_hash_handle hh;
} dap_chain_net_srv_banlist_item_t;

typedef struct dap_chain_net_srv
{
    dap_chain_net_srv_uid_t uid; // Unique ID for service.
    dap_chain_net_srv_abstract_t srv_common;
    dap_chain_net_srv_price_t *pricelist;

    uint32_t grace_period;
    pthread_mutex_t banlist_mutex;
    dap_chain_net_srv_banlist_item_t *ban_list;

    dap_chain_callback_trafic_t callback_trafic;

    // Request for usage
    dap_chain_net_srv_callback_data_t callback_requested;

    // Receipt first sign successfull
    dap_chain_net_srv_callback_data_t callback_response_success;

    // Response error
    dap_chain_net_srv_callback_data_t callback_response_error;

    // Receipt next sign succesfull
    dap_chain_net_srv_callback_data_t callback_receipt_next_success;

    // Stream CH callbacks - channed opened,ready for read, ready for write and closed
    dap_chain_net_srv_callback_ch_t      callback_stream_ch_opened;
    dap_chain_net_srv_callback_data_t callback_stream_ch_read;
    dap_chain_net_srv_callback_data_with_out_data_t callback_stream_ch_read_with_out_data;
    dap_chain_net_srv_callback_ch_t callback_stream_ch_write;
    dap_chain_net_srv_callback_ch_t      callback_stream_ch_closed;

    // Client have to start service
    dap_chain_net_srv_callback_data_t callback_client_success;
    // Client have to sign receipt
    dap_chain_net_srv_callback_sign_request_t callback_client_sign_request;

    // Pointer to inheritor object
    void * _inhertor;
} dap_chain_net_srv_t;

typedef struct dap_chain_net_srv_client_remote
{
    dap_stream_ch_t * ch; // Use ONLY in own context, not thread-safe
    time_t ts_created;
    dap_stream_worker_t * stream_worker;
    int session_id;
    dap_chain_net_remote_t *net_remote; // For remotes
    uint64_t bytes_received;
    uint64_t bytes_sent;
    struct dap_chain_net_srv_client_remote *prev;
    struct dap_chain_net_srv_client_remote *next;
} dap_chain_net_srv_client_remote_t;

typedef void (*dap_chain_net_srv_callback_new_t)(dap_chain_net_srv_t *, dap_config_t *);

int dap_chain_net_srv_init();
void dap_chain_net_srv_deinit(void);
dap_chain_net_srv_t* dap_chain_net_srv_add(dap_chain_net_srv_uid_t a_uid,dap_chain_net_srv_callback_data_t a_callback_requested,
                                           dap_chain_net_srv_callback_data_t a_callback_response_success,
                                           dap_chain_net_srv_callback_data_t a_callback_response_error,
                                           dap_chain_net_srv_callback_data_t a_callback_receipt_next_success
                                           );

int dap_chain_net_srv_set_ch_callbacks(dap_chain_net_srv_uid_t a_uid,
                                       dap_chain_net_srv_callback_ch_t a_callback_stream_ch_opened,
                                       dap_chain_net_srv_callback_data_t a_callback_stream_ch_read,
                                       dap_chain_net_srv_callback_data_with_out_data_t a_callback_stream_ch_read_with_out_data,
                                       dap_chain_net_srv_callback_ch_t a_callback_stream_ch_write,
                                       dap_chain_net_srv_callback_ch_t a_callback_stream_ch_closed
                                       );

void dap_chain_net_srv_del(dap_chain_net_srv_t * a_srv);
void dap_chain_net_srv_del_all(void);

void dap_chain_net_srv_call_write_all(dap_stream_ch_t * a_client);
void dap_chain_net_srv_call_closed_all(dap_stream_ch_t * a_client);
void dap_chain_net_srv_call_opened_all(dap_stream_ch_t * a_client);

dap_chain_net_srv_t * dap_chain_net_srv_get(dap_chain_net_srv_uid_t a_uid);
size_t dap_chain_net_srv_count(void);
const dap_chain_net_srv_uid_t * dap_chain_net_srv_list(void);
dap_chain_datum_tx_receipt_t * dap_chain_net_srv_issue_receipt(dap_chain_net_srv_t *a_srv,
                dap_chain_net_srv_usage_t * a_usage,
                dap_chain_net_srv_price_t * a_price, const void * a_ext, size_t a_ext_size
                );


int dap_chain_net_srv_remote_init(dap_chain_net_srv_uid_t a_uid,
        dap_chain_net_srv_callback_data_t a_callback_request,
        dap_chain_net_srv_callback_data_t a_callback_response_success,
        dap_chain_net_srv_callback_data_t a_callback_response_error,
        dap_chain_net_srv_callback_data_t a_callback_receipt_next_success,
        dap_chain_net_srv_callback_data_t a_callback_client_success,
        dap_chain_net_srv_callback_sign_request_t a_callback_client_sign_request,
        void *a_inhertor);
